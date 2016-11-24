# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200707-05.xml
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
 script_id(25680);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200707-05");
 script_cve_id("CVE-2007-3156");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200707-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200707-05
(Webmin, Usermin: Cross-site scripting vulnerabilities)


    The pam_login.cgi file does not properly sanitize user input before
    sending it back as output to the user.
  
Impact

    An unauthenticated attacker could entice a user to browse a specially
    crafted URL, allowing for the execution of script code in the context
    of the user\'s browser and for the theft of browser credentials. This
    may permit the attacker to login to Webmin or Usermin with the user\'s
    permissions.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Webmin users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --verbose --oneshot ">=app-admin/webmin-1.350"
    All Usermin users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --verbose --oneshot ">=app-admin/usermin-1.280"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3156');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200707-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200707-05] Webmin, Usermin: Cross-site scripting vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Webmin, Usermin: Cross-site scripting vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/usermin", unaffected: make_list("ge 1.280"), vulnerable: make_list("lt 1.280")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-admin/webmin", unaffected: make_list("ge 1.350"), vulnerable: make_list("lt 1.350")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
