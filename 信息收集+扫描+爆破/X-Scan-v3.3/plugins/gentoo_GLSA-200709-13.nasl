# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(26103);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200709-13");
 script_cve_id("CVE-2007-4091");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-13
(rsync: Two buffer overflows)


    Sebastian Krahmer from the SUSE Security Team discovered two off-by-one
    errors in the function "f_name()" in file sender.c when processing
    overly long directory names.
  
Impact

    A remote attacker could entice a user to synchronize a repository
    containing specially crafted directories, leading to the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All rsync users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/rsync-2.6.9-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4091');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-13] rsync: Two buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsync: Two buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/rsync", unaffected: make_list("ge 2.6.9-r3"), vulnerable: make_list("lt 2.6.9-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
