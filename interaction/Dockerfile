from ubuntu:18.04

#run apt-get -qq update && apt-get -qq --no-install-recommends install debconf
#run echo "tzdata  tzdata/Areas  select  America" | debconf-set-selections
#run echo "tzdata  tzdata/Zones/America  select  Los_Angeles" | debconf-set-selections
#run DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true apt-get install -qq --no-install-recommends sagemath

run apt-get -qq update && apt-get -qq --no-install-recommends install debconf
run echo "tzdata	tzdata/Areas	select	America" | debconf-set-selections
run echo "tzdata	tzdata/Zones/America	select	Los_Angeles" | debconf-set-selections
run DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true apt-get install -qq --no-install-recommends sagemath
run sage -python2 -m pip install pwntools pycryptodome

env PWNLIB_NOTERM true

COPY exploit.sage /exploit.sage
COPY sss /sss
