FROM ubuntu

WORKDIR /app

COPY execsnoop .

CMD [ "./execsnoop" ]
