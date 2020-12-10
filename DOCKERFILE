FROM python:3.7
MAINTAINER f5labs@f5.com
RUN pip3 install pycurl
RUN pip3 install cryptonice
ENTRYPOINT ["cryptonice" ]
CMD ["localhost"]
