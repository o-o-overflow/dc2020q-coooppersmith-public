from ubuntu:18.04

run apt-get -qq update && apt-get -qq --no-install-recommends install xinetd libssl1.0-dev libc6-dev gcc vim

# Note: anything that goes in public_files must be pre-built and checked in git
copy service /service
copy src/banner /banner
copy src/service.c /service.c

# the deployment tester will pass in the flag from the yaml
ARG THE_FLAG="OOO{Be_A_Flexible_Coppersmith}"
RUN touch /flag && chmod 644 /flag && echo $THE_FLAG > /flag

copy service.conf /service.conf
copy banner_fail /banner_fail
copy wrapper /wrapper

expose 5000
cmd ["/usr/sbin/xinetd", "-syslog", "local0", "-dontfork", "-f", "/service.conf"]
# ^^ If ps would be too revealing, replace with the line below.
#    AFAIK, this also disables the built-in printf(%n) protection, so YMMV.
#cmd chmod go-rwx /proc && /usr/sbin/xinetd -syslog local0 -dontfork -f /service.conf
