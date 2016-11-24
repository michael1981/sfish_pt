
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41140);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  SLES9-SP4: Security update for lprng (11603)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 11603");
 script_set_attribute(attribute: "description", value: '* There is a (small) memory leak in lpd which lets its
memory usage grow a bit for each print job until the
print system becomes unusable.
* Using lprng with a printcap provided via NIS/YP produced
following error: "Init_tempfile: bad tempdir
\'/var/spool/lpd/%P\'". This was caused by the function
"Init_tempfile()", which tried to create tmpfiles in the
spool directory, which was not expanded at this time.
Patched version creates tmpfiles in tmpdir, when spooldir
is not yet expanded.
');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch 11603");
script_end_attributes();

script_summary(english: "Check for the security advisory #11603");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"lprng-3.8.25-37.16", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
