# This script was automatically generated from the dsa-153
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14990);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "153");
 script_cve_id("CVE-2002-1110", "CVE-2002-1111", "CVE-2002-1112", "CVE-2002-1113", "CVE-2002-1114");
 script_bugtraq_id(5504, 5509, 5510, 5514, 5515, 5563, 5565);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-153 security update');
 script_set_attribute(attribute: 'description', value:
'Joao Gouveia discovered an uninitialized variable which was insecurely
used with file inclusions in the mantis package, a php based bug
tracking system.  The Debian Security Team found even more similar
problems.  When these occasions are exploited, a remote user is able
to execute arbitrary code under the webserver user id on the web
server hosting the mantis system.
Jeroen Latour discovered that Mantis did not check all user input,
especially if they do not come directly from form fields. This opens
up a wide variety of SQL poisoning vulnerabilities on systems without
magic_quotes_gpc enabled.  Most of these vulnerabilities are only
exploitable in a limited manner, since it is no longer possible to
execute multiple queries using one call to mysql_query().  There is
one query which can be tricked into changing an account\'s access
level.
Jeroen Latour also reported that it is possible to instruct Mantis to
show reporters only the bugs that they reported, by setting the
limit_reporters option to ON.  However, when formatting the output
suitable for printing, the program did not check the limit_reporters
option and thus allowed reporters to see the summaries of bugs they
did not report.
Jeroen Latour discovered that the page responsible for displaying a
list of bugs in a particular project, did not check whether the user
actually has access to the project, which is transmitted by a cookie
variable.  It accidentally trusted the fact that only projects
accessible to the user were listed in the drop-down menu.  This
provides a malicious user with an opportunity to display the bugs of a
private project selected.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-153');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mantis packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA153] DSA-153-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-153-1 mantis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mantis', release: '3.0', reference: '0.17.1-2.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
