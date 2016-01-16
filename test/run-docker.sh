#!/bin/bash
#
# Build and run a docker image for Boulder. This is suitable for running
# repeatedly during development because Docker will cache the image it builds,
# and will only re-do the minimum necessary.
#
# NOTE: Currently we're not able to effectively cache the DB setup steps,
# because setting up the DB depends on source files in the Boulder repo. So any
# time source files change, Docker treats that as potentially invalidating the
# steps that came after the COPY. In theory we could add a step that copies only
# the files necessary to do the migrations, run them, and then copy the rest of
# the source.
set -o errexit
cd $(dirname $0)/..

# helper function to return the state of the container (true if running, false if not)
is_running(){
	local name=$1
	local state=$(docker inspect --format "{{.State.Running}}" $name 2>/dev/null)

	if [[ "$state" == "false" ]]; then
		# the container is up but not running
		# we should remove it so we can bring up another
		docker rm $name
	fi
	echo $state
}

# helper function to get boot2docker ip if we are on a mac
hostip=0.0.0.0
if command -v boot2docker >/dev/null 2>&1 ; then
	hostip="$(boot2docker ip)"
fi
# if the DOCKER_HOST variable exists, lets get the host ip from that
if [[ ! -z "$DOCKER_HOST" ]]; then
	hostip="$(echo $DOCKER_HOST | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"
fi

# If FAKE_DNS is empty, we default to looking up hosts in /etc/hosts.
# If FAKE_DNS is an IP-address, all hostnames are resolved to this IP address.
if [ -z "${FAKE_DNS}" ] ; then
	FAKE_DNS=hosts
fi

if ! docker network ls | grep boulder >/dev/null; then
	docker network create boulder
fi

if [[ "$(is_running boulder-mysql)" != "true" ]]; then
	# bring up mysql mariadb container
	docker run -d \
		--net boulder \
		-p 127.0.0.1:$BOULDER_MYSQL_PORT:3306 \
		-e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
		--name boulder-mysql \
		mariadb:10
fi

if [[ "$(is_running boulder-rabbitmq)" != "true" ]]; then
	# bring up rabbitmq container
	docker run -d \
		--net boulder \
		-p 127.0.0.1:$BOULDER_RABBITMQ_PORT:5672 \
		--name boulder-rabbitmq \
		rabbitmq:3
fi

# build the boulder docker image
docker build --rm --force-rm -t letsencrypt/boulder .

# run the boulder container
# The excluding `-d` command makes the instance interactive, so you can kill
# the boulder container with Ctrl-C.
docker run --rm -it \
	--net boulder \
	-p 127.0.0.1:$BOULDER_PORT:4000 \
	-e MYSQL_CONTAINER=yes \
	-e FAKE_DNS="$FAKE_DNS" \
	--name boulder \
	letsencrypt/boulder
