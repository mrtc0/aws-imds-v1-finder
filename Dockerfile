FROM --platform=linux/amd64 amazonlinux:2

RUN yum install -y kmod \
  kernel-devel \
  xz
RUN amazon-linux-extras install BCC

WORKDIR /aws-imds-v1-finder

COPY bpf.c bpf.c
COPY snoop.py snoop.py

CMD ["python3", "-u", "snoop.py"]
