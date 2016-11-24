# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-05.xml
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
 script_id(20314);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200512-05");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-05
(Xmail: Privilege escalation through sendmail)


    iDEFENSE reported that the AddressFromAtPtr function in the
    sendmail program fails to check bounds on arguments passed from other
    functions, and as a result an exploitable stack overflow condition
    occurs when specifying the "-t" command line option.
  
Impact

    A local attacker can make a malicious call to sendmail,
    potentially resulting in code execution with elevated privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Xmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/xmail-1.22"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2943');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=321&type=vulnerabilities&flashstatus=true');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-05] Xmail: Privilege escalation through sendmail');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xmail: Privilege escalation through sendmail');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-mta/xmail", unaffected: make_list("ge 1.22"), vulnerable: make_list("lt 1.22")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
