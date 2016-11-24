# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-11.xml
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
 script_id(22169);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200608-11");
 script_cve_id("CVE-2006-3392");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-11
(Webmin, Usermin: File Disclosure)


    A vulnerability in both Webmin and Usermin has been discovered by Kenny
    Chen, wherein simplify_path is called before the HTML is decoded.
  
Impact

    A non-authenticated user can read any file on the server using a
    specially crafted URL.
  
Workaround

    For a temporary workaround, IP Access Control can be setup on Webmin
    and Usermin.
  
');
script_set_attribute(attribute:'solution', value: '
    All Webmin users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --verbose --oneshot ">=app-admin/webmin-1.290"
    All Usermin users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --verbose --oneshot ">=app-admin/usermin-1.220"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-11] Webmin, Usermin: File Disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Webmin, Usermin: File Disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/usermin", unaffected: make_list("ge 1.220"), vulnerable: make_list("lt 1.220")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-admin/webmin", unaffected: make_list("ge 1.290"), vulnerable: make_list("lt 1.290")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
