
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7976
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34184);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-7976: libHX");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7976 (libHX)");
 script_set_attribute(attribute: "description", value: "A library for:
- rbtree with key-value pair extension
- deques (double-ended queues) (Stacks (LIFO) / Queues (FIFOs))
- platform independent opendir-style directory access
- platform independent dlopen-style shared library access
- auto-storage strings with direct access
- command line option (argv) parser
- shconfig-style config file parser
- platform independent random number generator with transparent
/dev/urandom support
- various string, memory and zvec ops

-
Update Information:

A security flaw in the pam_mount's handling of user defined volumes using the
'luserconf' option has been fixed in this update. The vulnerability allowed
users to arbitrarily mount filesystems at arbitrary locations.    More details
about this vulnerability can be found in the announcement message sent to the
pam-mount-user mailinglist at SourceForge: [9]http://sourceforge.net/mailarchiv
e/me
ssage.php?msg_name=alpine.LNX.1.10.0809042353120.17569%40fbirervta.pbzchgretzou
.
qr    Upstream changelog (excluding the git shortlog) for versions 0.43-0.47:
- mount.crypt: fix option slurping (SF bug #2054323)  - properly handle simple
sgrp config items (Debian bug #493497)  - src: correct error check in run_lsof(
)
- conf: check that slash follows home tilde  - conf: wildcard inadvertently
matched root sometimes  - fix double-freeing the authentication token  - use of
l
instead of lsof/fuser  - kill-on-logout support (terminate processes that would
stand in the    way of unmounting)  - mount.crypt: auto-detect necessity for
running losetup  - mount.crypt: add missing null command to conform to sh synta
x
(SF bug #2089446)  - conf: fix printing of strings when luser volume options
were not ok  - conf: re-add luserconf security checks  - add support for encfs
1.3.x (1.4.x already has been in for long)  - conf: add the 'noroot' attribute
for <volume> to force mounting with    the unprivileged user account (required
for FUSE filesystems)  - replace fixed-size buffers and arrays with dynamic one
s
(complete)    Note: This update also introduces a new version of libHX, which i
s
required by updated pam_mount.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the libHX package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libHX-1.23-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
