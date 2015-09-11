# ################################
# Makefile for compiling resources
# files.
# TODO move to setup scripts
# and implement it in python
# http://die-offenbachs.homelinux.org:48888/hg/eric5/file/5072605ad4dd/compileUiFiles.py
###### EDIT ######################

#Directory with ui and resource files
RESOURCE_DIR = data/resources
UI_DIR = src/leap/bitmask/gui/ui

#Directory for compiled resources
COMPILED_DIR = src/leap/bitmask/gui

#Directory for (finished) translations
TRANSLAT_DIR = data/translations

#Project file, used for translations
PROJFILE = data/bitmask.pro

# UI files to compile
UI_FILES = \
  loggerwindow.ui \
  wizard.ui \
  mainwindow.ui login.ui eip_status.ui mail_status.ui \
  preferences.ui \
    preferences_account_page.ui \
    preferences_vpn_page.ui \
    preferences_email_page.ui \
    password_change.ui \
    advanced_key_management.ui

# Qt resource files to compile
RESOURCES = icons.qrc flags.qrc locale.qrc loggerwindow.qrc

#pyuic4 and pyrcc4 binaries
PYUIC = pyside-uic
PYRCC = pyside-rcc
PYLUP = pyside-lupdate
LRELE = lrelease


#################################
# DO NOT EDIT FOLLOWING

LEAP_REPOS = leap_pycommon keymanager leap_mail soledad

COMPILED_UI = $(UI_FILES:%.ui=$(COMPILED_DIR)/ui_%.py)
COMPILED_RESOURCES = $(RESOURCES:%.qrc=$(COMPILED_DIR)/%_rc.py)

DEBVER = $(shell dpkg-parsechangelog | sed -ne 's,Version: ,,p')

ifndef EDITOR
	export EDITOR=vim
endif

ifndef RESOURCE_TIME
	export RESOURCE_TIME=10
endif

CURDIR = $(shell pwd)

###########################################

all : resources ui

resources : $(COMPILED_RESOURCES)

ui : $(COMPILED_UI)

translations:
	data/make_project_file.py
	$(PYLUP) $(PROJFILE)
	$(LRELE) $(TRANSLAT_DIR)/*.ts

$(COMPILED_DIR)/ui_%.py : $(UI_DIR)/%.ui
	$(PYUIC) $< -o $@

$(COMPILED_DIR)/%_rc.py : $(RESOURCE_DIR)/%.qrc
	$(PYRCC) $< -o $@


manpages:
	rst2man docs/man/bitmask.1.rst docs/man/bitmask.1

apidocs:
	@sphinx-apidoc -o docs/api src/leap/bitmask

do_cprofile:
	python -m cProfile -o bitmask.cprofile src/leap/bitmask/app.py --debug -N

view_cprofile:
	cprofilev bitmask.cprofile

mailprofile:
	gprof2dot -f pstats /tmp/leap_mail_profile.pstats -n 0.2 -e 0.2 | dot -Tpdf -o /tmp/leap_mail_profile.pdf

do_lineprof:
	LEAP_PROFILE_IMAPCMD=1 LEAP_MAIL_MANHOLE=1 kernprof.py -l src/leap/bitmask/app.py --debug

do_lineprof_offline:
	LEAP_PROFILE_IMAPCMD=1 LEAP_MAIL_MANHOLE=1 kernprof.py -l src/leap/bitmask/app.py --offline --debug -N

view_lineprof:
	@python -m line_profiler app.py.lprof | $(EDITOR) -

resource_graph:
	#./pkg/scripts/monitor_resource.zsh `ps aux | grep app.py | head -1 | awk '{print $$2}'` $(RESOURCE_TIME)
	./pkg/scripts/monitor_resource.zsh `pgrep bitmask` $(RESOURCE_TIME)
	display bitmask-resources.png

get_wheels:
	pip install --upgrade setuptools
	pip install --upgrade pip
	pip install wheel

gather_wheels:
	pip wheel --wheel-dir=../wheelhouse pyzmq --build-option "--zmq=bundled"
	# because fuck u1db externals, that's why...
	pip wheel --wheel-dir=../wheelhouse --allow-external dirspec --allow-unverified dirspec --allow-external u1db --allow-unverified u1db -r pkg/requirements.pip

install_wheel:
	# if it's the first time, you'll need to get_wheels first
	pip install --pre --use-wheel --no-index --find-links=../wheelhouse -r pkg/requirements.pip

gather_deps:
	pipdeptree | pkg/scripts/filter-bitmask-deps

install_base_deps:
	for repo in leap_pycommon keymanager leap_mail soledad/common soledad/client; do cd $(CURDIR)/../$$repo && pkg/pip_install_requirements.sh; done
	pkg/pip_install_requirements.sh

pull_leapdeps:
	for repo in $(LEAP_REPOS); do cd $(CURDIR)/../$$repo && git pull; done

checkout_leapdeps_develop:
	for repo in $(LEAP_REPOS); do cd $(CURDIR)/../$$repo && git checkout develop; done
	git checkout develop

checkout_leapdeps_release:
	pkg/scripts/checkout_leap_versions.sh

setup_without_namespace:
	awk '!/namespace_packages*/' setup.py > file && mv file setup.py

sumo_tarball_release: checkout_leapdeps_release setup_without_namespace
	python setup.py sdist --sumo
	git checkout -- src/leap/__init__.py
	git checkout -- src/leap/bitmask/_version.py
	rm -rf src/leap/soledad
	git checkout -- setup.py

# XXX We need two sets of sumo-tarballs: the one published for a release
# (that will pick the pinned leap deps), and the other which will be used
# for the nightly builds.
# TODO change naming scheme for sumo-latest: should include date (in case
# bitmask is not updated bu the dependencies are)

sumo_tarball_latest: checkout_leapdeps_develop pull_leapdeps setup_without_namespace
	python setup.py sdist --sumo   # --latest
	git checkout -- src/leap/__init__.py
	git checkout -- src/leap/bitmask/_version.py
	rm -rf src/leap/soledad
	git checkout -- setup.py

pyinst:
	pyinstaller -y pkg/pyinst/bitmask.spec

pyinst-oks:
	pyinstaller -y pkg/pyinst/bitmask.spec
	mkdir -p dist/Bitmask.app/Contents/MacOS/cryptography/hazmat/bindings/openssl/src/
	cp pkg/pyinst/cryptography/osrandom_engine.* dist/Bitmask.app/Contents/MacOS/cryptography/hazmat/bindings/openssl/src/
	mv dist/Bitmask.app/Contents/MacOS/bitmask dist/Bitmask.app/Contents/MacOS/bitmask-app
	cp pkg/osx/bitmask-wrapper dist/Bitmask.app/Contents/MacOS/bitmask

clean_pkg:
	rm -rf build dist

clean :
	$(RM) $(COMPILED_UI) $(COMPILED_RESOURCES) $(COMPILED_UI:.py=.pyc) $(COMPILED_RESOURCES:.py=.pyc)
