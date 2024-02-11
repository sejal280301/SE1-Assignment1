FROM ubuntu:16.04
      
MAINTAINER Sejal Manoj Utekar <sejalmanoj.utekar@mailbox.tu-dresden.de>

RUN apt-get update && apt-get upgrade -y

# Install necessary packages
RUN apt-get update && apt-get install -y openssh-server sudo

RUN  apt-get install -y wget libmemcached-tools git r-base

# Expose SSH port to external port 10022
EXPOSE 22

RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 ubuntu\
    && echo "ubuntu:ubuntu" | chpasswd


RUN chown -R ubuntu:sudo /home/ubuntu/

RUN mkdir -p /home/ubuntu/.ssh && \
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCWon3JclSmDGqeAFmZpdeL2sFgYtQt0/iMPpSryRB8imJHiOlrzlzHdxgIYGiv4p3WeR9bWi0fuSGx7vZP570v8TP8oW87GZ0NeUO9URsJaKUu8qlciPJ/vS4KWcbMV0A+R/YYvvtT0u3Lk0/DbZoojrEaEXRwr32o4KfFtkipWjp338y7YeDGEwjFiiSRakNpVLNULQlirAVKtYFztFEDwQ6m1z0DLixvF/veskkhwLq39URA4+d/UqF+awxif++mt4xiXn9ToWUzdQdkP9cKCyUQfYJ8mC0rItyP4KRRQR1fVSGuJbi8qG2ScctiZ+bDIXQbWBG9aq5QZugVWLAxZP1pTma4ENU+47fVkSpIIlkvnuDVKBrCCHenGHtcj/g0d/RERwZ03RPNbtlgEOKGsDNCqUwo+irjFH1jc4lAI/pKowKP1u9sgkru0IgTC9EPepi2ebCxime+GKex9d6iq4TAx2SccsqcQjNrgQQmZGEUFpQ3CFhiaoWe+xzVrNU= sejalutekar@edr20308.dip.tu-dresden.de" > /home/ubuntu/.ssh/authorized_keys
    # Add CI's public SSH key
RUN echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDcFj9AJ0yx2NswwEKPFQZqpiYZ8Mzk1LlRNatsVQqUfaDoQTKewuHRpp5jREB9RIMPczgFPDZSOBQ+mV8u5qJScmOcB8rhaF0GZkF1KIgHSNj8VqDNZWP52m1+NxSJetp6Opu3zTzkoZt9uo4HHeVZseTfN0UkxSjcWKYPX7+rOrvMhIxxKB9bR7UjmMkmoMfzP8UVkmc4MxIOo+RW9OM9GFselGN9JTYceZW8xhWNH2ENXQNWE5a807vP6kaKWp5bQ/c7NpISvTAO5UaVD26IRrtqea//MiUORjbXX+dEpFZuN6fRMh+zemerQ9rDHcgxRMacGZxBUjIRCa92zSr3 gitlab-runner@sep" >> /home/ubuntu/.ssh/authorized_keys
# Create a non-root user 'ubuntu' with UID 1000 and set ownership of the SSH directory
RUN chown -R ubuntu:sudo /home/ubuntu/.ssh


# Set up SSH
RUN mkdir /var/run/sshd 
    # && sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    # && sed -i 's/Port 22/Port 22/' /etc/ssh/sshd_config

# Install Memcached benchmark client (mcperf)
WORKDIR /home/ubuntu


RUN wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/twemperf/mcperf-0.1.1.tar.gz \
	&& tar xzf mcperf-0.1.1.tar.gz \
	&& cd mcperf-0.1.1 \
	&& ./configure \
	&& make \
	&& sudo make install

RUN git clone https://bitbucket.org/db7/dude \
	&& cd dude \
	&& python setup.py install

COPY id_rsa /home/ubuntu/.ssh/id_rsa
RUN  chown ubuntu:sudo /home/ubuntu/.ssh/id_rsa
COPY run.sh /home/ubuntu/run.sh
COPY graphs.R /home/ubuntu/graphs.R
COPY Dudefile /home/ubuntu/Dudefile
COPY Benchmark.py /home/ubuntu/Benchmark.py
RUN chmod 777 /home/ubuntu/run.sh




# Start the SSH Server
CMD ["/usr/sbin/sshd", "-D"]

