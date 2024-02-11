FROM ubuntu:16.04
      
MAINTAINER Sejal Manoj Utekar <sejalmanoj.utekar@mailbox.tu-dresden.de>

RUN apt-get update
RUN apt-get upgrade -y

# Install necessary packages
RUN apt-get update \
    && apt-get install -y \
        openssh-server \
        build-essential \
        libevent-dev \
        wget \
        sudo

# Create a non-root user (Ubuntu with uid 1000)
RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 ubuntu\
    && echo "ubuntu:ubuntu" | chpasswd


RUN chown -R ubuntu:sudo /home/ubuntu/

# Set up SSH
RUN mkdir /var/run/sshd
# RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
# RUN sed -i 's/Port 22/Port 20022/' /etc/ssh/sshd_config
RUN mkdir -p /home/ubuntu/.ssh
    # Add CI's public SSH key
RUN echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDcFj9AJ0yx2NswwEKPFQZqpiYZ8Mzk1LlRNatsVQqUfaDoQTKewuHRpp5jREB9RIMPczgFPDZSOBQ+mV8u5qJScmOcB8rhaF0GZkF1KIgHSNj8VqDNZWP52m1+NxSJetp6Opu3zTzkoZt9uo4HHeVZseTfN0UkxSjcWKYPX7+rOrvMhIxxKB9bR7UjmMkmoMfzP8UVkmc4MxIOo+RW9OM9GFselGN9JTYceZW8xhWNH2ENXQNWE5a807vP6kaKWp5bQ/c7NpISvTAO5UaVD26IRrtqea//MiUORjbXX+dEpFZuN6fRMh+zemerQ9rDHcgxRMacGZxBUjIRCa92zSr3 gitlab-runner@sep" > /home/ubuntu/.ssh/authorized_keys
RUN echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCWon3JclSmDGqeAFmZpdeL2sFgYtQt0/iMPpSryRB8imJHiOlrzlzHdxgIYGiv4p3WeR9bWi0fuSGx7vZP570v8TP8oW87GZ0NeUO9URsJaKUu8qlciPJ/vS4KWcbMV0A+R/YYvvtT0u3Lk0/DbZoojrEaEXRwr32o4KfFtkipWjp338y7YeDGEwjFiiSRakNpVLNULQlirAVKtYFztFEDwQ6m1z0DLixvF/veskkhwLq39URA4+d/UqF+awxif++mt4xiXn9ToWUzdQdkP9cKCyUQfYJ8mC0rItyP4KRRQR1fVSGuJbi8qG2ScctiZ+bDIXQbWBG9aq5QZugVWLAxZP1pTma4ENU+47fVkSpIIlkvnuDVKBrCCHenGHtcj/g0d/RERwZ03RPNbtlgEOKGsDNCqUwo+irjFH1jc4lAI/pKowKP1u9sgkru0IgTC9EPepi2ebCxime+GKex9d6iq4TAx2SccsqcQjNrgQQmZGEUFpQ3CFhiaoWe+xzVrNU= sejalutekar@edr20308.dip.tu-dresden.de" >> /home/ubuntu/.ssh/authorized_keys

RUN chown -R ubuntu:sudo /home/ubuntu/.ssh

# Build and install memcached from source
WORKDIR /home/ubuntu

RUN wget http://www.memcached.org/files/memcached-1.4.33.tar.gz \
    && tar -zxvf memcached-1.4.33.tar.gz \
    && cd memcached-1.4.33 \
    && ./configure \
    && make \
    && make install \
    && cd / \
    && rm -rf /tmp/memcached-1.4.33

# Expose ports for SSH Server and memcached
EXPOSE 22 11211

# Start SSH Server
CMD ["/usr/sbin/sshd", "-D"]

