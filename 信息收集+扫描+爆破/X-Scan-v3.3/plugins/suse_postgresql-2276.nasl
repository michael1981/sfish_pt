
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29557);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for PostgreSQL (postgresql-2276)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch postgresql-2276");
 script_set_attribute(attribute: "description", value: "The SQL Server PostgreSQL has been updated to fix the
following security problems:

CVE-2006-5540: backend/parser/analyze.c in PostgreSQL 8.1.x
allowed remote authenticated users to cause a denial of
service (daemon crash) via certain aggregate functions in
an UPDATE statement, which are not properly handled during
a 'MIN/MAX index optimization.'

CVE-2006-5541: backend/parser/parse_coerce.c in PostgreSQL
7.4.1 through 7.4.14, 8.0.x before 8.0.9, and 8.1.x before
8.1.5 allows remote authenticated users to cause a denial
of service (daemon crash) via a coercion of an unknown
element to ANYARRAY.

CVE-2006-5542: backend/tcop/postgres.c in PostgreSQL 8.1.x
before 8.1.5 allows remote authenticated users to cause a
denial of service (daemon crash) related to duration
logging of V3-protocol Execute messages for (1) COMMIT and
(2) ROLLBACK SQL statements.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch postgresql-2276");
script_end_attributes();

script_cve_id("CVE-2006-5540", "CVE-2006-5541", "CVE-2006-5542");
script_summary(english: "Check for the postgresql-2276 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"postgresql-8.1.4-1.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.1.4-1.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.1.4-1.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.1.4-1.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-libs-8.1.4-1.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-pl-8.1.4-1.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.1.4-1.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.1.4-1.6", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-libs-8.1.4-1.6", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
