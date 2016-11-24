# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-17.xml
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
 script_id(23874);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200612-17");
 script_cve_id("CVE-2006-4181");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-17
(GNU Radius: Format string vulnerability)


    A format string vulnerability was found in the sqllog function from the
    SQL accounting code for radiusd. That function is only used if one or
    more of the "postgresql", "mysql" or "odbc" USE flags are enabled,
    which is not the default, except for the "server" 2006.1 and 2007.0
    profiles which enable the "mysql" USE flag.
  
Impact

    An unauthenticated remote attacker could execute arbitrary code with
    the privileges of the user running radiusd, which may be the root user.
    It is important to note that there is no default GNU Radius user for
    Gentoo systems because no init script is provided with the package.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GNU Radius users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dialup/gnuradius-1.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4181');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-17] GNU Radius: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNU Radius: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dialup/gnuradius", unaffected: make_list("ge 1.4"), vulnerable: make_list("lt 1.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
