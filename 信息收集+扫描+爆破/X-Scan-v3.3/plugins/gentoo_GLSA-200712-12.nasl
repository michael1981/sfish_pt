# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-12.xml
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
 script_id(29717);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200712-12");
 script_cve_id("CVE-2007-6122");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-12
(IRC Services: Denial of Service)


    loverboy reported that the "default_encrypt()" function in file
    encrypt.c does not properly handle overly long passwords.
  
Impact

    A remote attacker could provide an overly long password to the
    vulnerable server, resulting in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All IRC Services users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-irc/ircservices-5.0.63"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6122');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-12] IRC Services: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'IRC Services: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-irc/ircservices", unaffected: make_list("ge 5.0.63"), vulnerable: make_list("lt 5.0.63")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
