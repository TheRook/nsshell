#!/usr/bin/make
# WARN: gmake syntax
########################################################
#
# useful targets:
#   make test   - run the unit tests
#   make flake8 - linting and pep8
#   make docs 	- create manpages and html documentation

########################################################
# variable section

NAME = nsshell
OS = $(shell uname -s)
ARCHITECTURE = amd64
VERSION= $(shell grep -e 'version=' setup.py | cut -d\' -f 2)
PYTHON = $(shell which python2)
VIRTUALENV_PATH = $(shell echo $$HOME/.virtualenvs)
INSTALL_PATH = /usr/local/lib
EXEC_PATH = /usr/local/bin

MANPAGES=$(wildcard docs/man/**/*.*.ronn)
MANPAGES_GEN=$(patsubst %.ronn,%,$(MANPAGES))
MANPAGES_HTML=$(patsubst %.ronn,%.html,$(MANPAGES))
ifneq ($(shell which ronn 2>/dev/null),)
RONN2MAN = ronn
else
RONN2MAN = @echo "WARN: 'ronn' command is not installed but is required to build $(MANPAGES)"
endif

UNITTESTS=unittest
COVERAGE=coverage

########################################################


docs: $(MANPAGES)
	$(RONN2MAN) $^

.PHONY: clean
clean:
	rm -f $(MANPAGES_GEN) $(MANPAGES_HTML)
	rm -rf ./build
	rm -rf ./dist
	rm -rf ./*.egg-info
	rm -rf ./*.deb
	rm -rf .tox 
	rm -rf .coverage 
	rm -rf .cache
	find . -name '*.pyc.*' -delete
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

test:
	# "TODO - test"

virtualenv:
	mkdir -p $(VIRTUALENV_PATH)
	rm -rf $(VIRTUALENV_PATH)/$(NAME)
	virtualenv -p $(PYTHON) $(VIRTUALENV_PATH)/$(NAME)

virtualenv-install: virtualenv
	$(VIRTUALENV_PATH)/$(NAME)/bin/python setup.py install

virtualenv-develop: virtualenv
	$(VIRTUALENV_PATH)/$(NAME)/bin/python setup.py develop

virtualenv-sdist: virtualenv
	$(VIRTUALENV_PATH)/$(NAME)/bin/python setup.py sdist

dist: install
	fpm -s dir -t deb -v $(VERSION) -n $(NAME) -a $(ARCHITECTURE) $(INSTALL_PATH)/$(NAME) $(EXEC_PATH)/$(NAME)

install:
	virtualenv -p $(PYTHON) $(INSTALL_PATH)/$(NAME)
	$(INSTALL_PATH)/$(NAME)/bin/python setup.py install
	ln -f -s $(INSTALL_PATH)/$(NAME)/bin/$(NAME) $(EXEC_PATH)/$(NAME)
	# look at my templating language ma
	mkdir -p /etc/nsshell
	mkdir -p /var/log/nsshell
	echo -n '[a]\nSCRIPTS_DIR="/etc/nsshell/scripts/"\nLOG_DIR="/var/log/nsshell"' > /etc/nsshell/nsshell.conf
	cp -r scripts/ /etc/nsshell/

uninstall:
	rm -rf -v -I $(INSTALL_PATH)/$(NAME)
	rm -f -v -I $(EXEC_PATH)/$(NAME)

container:
	bash ./scripts/build.sh -d
	bash ./scripts/build.sh -b

all: docs test
