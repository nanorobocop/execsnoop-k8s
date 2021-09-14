package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"C"
	bpf "github.com/iovisor/gobpf/bcc"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

//go:embed execsnoop.cc
var execsnoop string

type EventType int32

type (
	Container struct {
		ID        string
		PID       int
		PPID      int
		Name      string
		Pod       string
		Namespace string
		Deleted   bool
	}
)

const (
	eventArg EventType = iota
	eventRet

	traceFailed = true
	filterComm  = ""
	filterArg   = ""
	quotemarks  = false
)

type execveEvent struct {
	Pid    uint64
	Ppid   uint64
	Comm   [16]byte
	Type   int32
	Argv   [128]byte
	RetVal int32
}

type eventPayload struct {
	Time   string `json:"time,omitempty"`
	Comm   string `json:"comm"`
	Pid    uint64 `json:"pid"`
	Ppid   string `json:"ppid"`
	Argv   string `json:"argv"`
	RetVal int32  `json:"retval"`
}

func getPpid(pid uint64) uint64 {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/status", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		text := sc.Text()
		if strings.Contains(text, "PPid:") {
			f := strings.Fields(text)
			i, _ := strconv.ParseUint(f[len(f)-1], 10, 64)
			return i
		}
	}
	return 0
}

func main() {

	//content, err := ioutil.ReadFile("execsnoop.cc")
	//if err != nil {
	//	fmt.Printf("Failed to read file: %+v", err)
	//	os.Exit(1)
	//}


	m := bpf.NewModule(strings.Replace(execsnoop, "MAX_ARGS", strconv.FormatUint(20, 10), -1), []string{})
	defer m.Close()

	fnName := bpf.GetSyscallFnName("execve")

	kprobe, err := m.LoadKprobe("syscall__execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load syscall__execve: %s\n", err)
		os.Exit(1)
	}
	// passing -1 for maxActive signifies to use the default
	// according to the kernel kprobes documentation
	if err := m.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach syscall__execve: %s\n", err)
		os.Exit(1)
	}

	kretprobe, err := m.LoadKprobe("do_ret_sys_execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	// passing -1 for maxActive signifies to use the default
	// according to the kernel kretprobes documentation
	if err := m.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("events"), m)

	procsCh := make(chan []byte, 1000)

	perfMap, err := bpf.InitPerfMap(table, procsCh, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	perfMap.Start()

	containersCh := make(chan Container)
	go watchContainers(containersCh)

	containers := map[string]Container{}

	args := make(map[uint64][]string)
	for {
		select {
		case <-sig:
			perfMap.Stop()
			os.Exit(0)
		case c := <-containersCh:
			if c.Deleted {
				delete(containers, c.ID)
				continue
			}
			c.PPID = int(getPpid(uint64(c.PID)))
			containers[c.ID] = c
			fmt.Printf("%s %d %d %s %s %s\n", c.ID, c.PID, c.PPID, c.Namespace, c.Pod, c.Name)
		case data := <-procsCh:
			var event execveEvent
			err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)

			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}

			if eventArg == EventType(event.Type) {
				e, ok := args[event.Pid]
				if !ok {
					e = make([]string, 0)
				}
				argv := (*C.char)(unsafe.Pointer(&event.Argv))

				e = append(e, C.GoString(argv))
				args[event.Pid] = e
			} else {
				if event.RetVal != 0 && !traceFailed {
					delete(args, event.Pid)
					continue
				}

				comm := C.GoString((*C.char)(unsafe.Pointer(&event.Comm)))
				if filterComm != "" && !strings.Contains(comm, filterComm) {
					delete(args, event.Pid)
					continue
				}

				argv, ok := args[event.Pid]
				if !ok {
					continue
				}

				if filterArg != "" && !strings.Contains(strings.Join(argv, " "), filterArg) {
					delete(args, event.Pid)
					continue
				}

				p := eventPayload{
					Pid:    event.Pid,
					Ppid:   "?",
					Comm:   comm,
					RetVal: event.RetVal,
				}

				if event.Ppid == 0 {
					event.Ppid = getPpid(event.Pid)
				}

				if event.Ppid != 0 {
					p.Ppid = strconv.FormatUint(event.Ppid, 10)
				}

				if quotemarks {
					var b bytes.Buffer
					for i, a := range argv {
						b.WriteString(strings.Replace(a, `"`, `\"`, -1))
						if i != len(argv)-1 {
							b.WriteString(" ")
						}
					}
					p.Argv = b.String()
				} else {
					p.Argv = strings.Join(argv, " ")
				}
				p.Argv = strings.TrimSpace(strings.Replace(p.Argv, "\n", "\\n", -1))

				fmt.Printf("PROC::: %+v\n", p)
				for _, c := range containers {
					if isAncestor(int(p.Pid), c.PPID) {
						fmt.Printf("Found exec: %s / %s / %s executed \"%s\"\n", c.Namespace, c.Pod, c.Name, p.Argv)
						break
					}
				}
				delete(args, event.Pid)
			}
		}
	}
}

// isAncestor checks if pid is successtor of ancestor
func isAncestor(pid, ancestor int) bool {
	for {
		ppid := int(getPpid(uint64(pid)))
		if ppid == 0 {
			//fmt.Printf("Failed to find parent pid for %d\n", pid)
			return false
		}
		if ppid == ancestor {
			return true
		}
		pid = ppid
		if pid == 1 {
			return false
		}
	}
}

func watchContainers(containersCh chan<- Container) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}

	since := time.Now()

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}

	for _, container := range containers {
		if cname, pname, nsname, ok := isK8sContainer(container.Labels); ok {
			json, err := cli.ContainerInspect(context.Background(), container.ID)
			if err != nil {
				fmt.Printf("Failed to inspect container: %+v\n", err)
				continue
			}
			pid := json.State.Pid
			containersCh <- Container{
				ID:        container.ID,
				Name:      cname,
				PID:       pid,
				Pod:       pname,
				Namespace: nsname,
			}
		}
	}

	// TODO: specify filter args (mansur)
	msgsCh, errsCh := cli.Events(context.Background(), types.EventsOptions{
		Since:   since.Format(time.RFC3339),
		Until:   "",
		Filters: filters.Args{},
	})

	for {
		select {
		case msg := <-msgsCh:
			if msg.Type != events.ContainerEventType {
				continue
			}

			fmt.Println(msg)
			if msg.Status == "create" {
				json, err := cli.ContainerInspect(context.Background(), msg.ID)
				if err != nil {
					fmt.Printf("Failed to inspect container: %+v\n", err)
					continue
				}

				if cname, pname, nsname, ok := isK8sContainer(json.Config.Labels); ok {
					pid := json.State.Pid
					containersCh <- Container{
						ID:        msg.ID,
						Name:      cname,
						PID:       pid,
						Pod:       pname,
						Namespace: nsname,
					}
				}
			}
			if msg.Status == "destroy" {
				containersCh <- Container{
					ID:      msg.ID,
					Deleted: true,
				}
			}

		case err := <-errsCh:
			fmt.Println(err)
		}
	}
}

func isK8sContainer(l map[string]string) (cname, pname, nsname string, ok bool) {
	if cname, ok = l["io.kubernetes.container.name"]; !ok {
		return "", "", "", false
	}
	if pname, ok = l["io.kubernetes.pod.name"]; !ok {
		return "", "", "", false
	}
	if nsname, ok = l["io.kubernetes.pod.namespace"]; !ok {
		return "", "", "", false
	}
	return cname, pname, nsname, true
}
