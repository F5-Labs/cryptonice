FROM python:3
MAINTAINER f5labs@f5.com
RUN pip3 install cryptonice
ENTRYPOINT ["cryptonice" ]
CMD ["localhost"]
