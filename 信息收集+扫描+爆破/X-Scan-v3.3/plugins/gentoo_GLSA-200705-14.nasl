# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-14.xml
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
 script_id(25235);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200705-14");
 script_cve_id("CVE-2007-1859");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-14
(XScreenSaver: Privilege escalation)


    XScreenSaver incorrectly handles the results of the getpwuid() function
    in drivers/lock.c when using directory servers during a network outage.
  
Impact

    A local user can crash XScreenSaver by preventing network connectivity
    if the system uses a remote directory service for credentials such as
    NIS or LDAP, which will unlock the screen.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All XScreenSaver users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-misc/xscreensaver-5.02"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1859');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-14] XScreenSaver: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XScreenSaver: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-misc/xscreensaver", unaffected: make_list("ge 5.02"), vulnerable: make_list("lt 5.02")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
