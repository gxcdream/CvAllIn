TEMPLATE = subdirs

SUBDIRS += lib
SUBDIRS += example

example.depend = lib

DISTFILES += \
    uncrustify.cfg


