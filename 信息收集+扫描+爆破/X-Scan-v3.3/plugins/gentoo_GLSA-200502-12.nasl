# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-12.xml
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
 script_id(16449);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-12");
 script_cve_id("CVE-2005-0427");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-12
(Webmin: Information leak in Gentoo binary package)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered that
    the Webmin ebuild contains a design flaw. It imports the encrypted
    local root password into the miniserv.users file before building binary
    packages that include this file.
  
Impact

    A remote attacker could retrieve Portage-built Webmin binary packages
    and recover the encrypted root password from the build host.
  
Workaround

    Users who never built or shared a Webmin binary package are unaffected
    by this.
  
');
script_set_attribute(attribute:'solution', value: '
    Webmin users should delete any old shared Webmin binary package as soon
    as possible. They should also consider their buildhost root password
    potentially exposed and follow proper audit procedures.
    If you plan to build binary packages, you should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/webmin-1.170-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0427');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-12] Webmin: Information leak in Gentoo binary package');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Webmin: Information leak in Gentoo binary package');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/webmin", unaffected: make_list("ge 1.170-r3"), vulnerable: make_list("lt 1.170-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
