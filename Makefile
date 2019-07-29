PROJECT = keccakf1600
PROJECT_DESCRIPTION = Keccak-f[1600] NIF with timeslice reductions for Erlang and Elixir.
PROJECT_VERSION = 3.0.0

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-shell docker-test

DOCKER_OTP_VERSION ?= 22.0

docker-build::
	$(gen_verbose) docker build \
		-t docker-otp-${DOCKER_OTP_VERSION} \
		-f test/Dockerfile \
		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
		test

docker-load::
	$(gen_verbose) docker load \
		-i "docker-otp-${DOCKER_OTP_VERSION}/image.tar"

docker-save::
	$(verbose) mkdir -p "docker-otp-${DOCKER_OTP_VERSION}"
	$(gen_verbose) docker save \
		-o "docker-otp-${DOCKER_OTP_VERSION}/image.tar" \
		docker-otp-${DOCKER_OTP_VERSION}

docker-setup::
	$(verbose) if [ -f "docker-otp-${DOCKER_OTP_VERSION}/image.tar" ]; then \
		$(MAKE) docker-load; \
	else \
		$(MAKE) docker-build; \
		$(MAKE) docker-save; \
	fi

docker-shell::
	$(verbose) docker run \
		-v "$(shell pwd)":"/build/keccakf1600" --rm -it "docker-otp-${DOCKER_OTP_VERSION}" \
		/bin/bash -l

docker-test::
	$(gen_verbose) docker run \
		-v "$(shell pwd)":"/build/keccakf1600" "docker-otp-${DOCKER_OTP_VERSION}" \
		sh -c 'cd keccakf1600 && make tests'
