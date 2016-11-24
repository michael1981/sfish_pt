# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-05.xml
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
 script_id(14652);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200409-05");
 script_cve_id("CVE-2004-1466");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-05
(Gallery: Arbitrary command execution)


    The upload handling code in Gallery places uploaded files in a
    temporary directory. After 30 seconds, these files are deleted if they
    are not valid images. However, since the file exists for 30 seconds, a
    carefully crafted script could be initiated by the remote attacker
    during this 30 second timeout. Note that the temporary directory has to
    be located inside the webroot and an attacker needs to have upload
    rights either as an authenticated user or via "EVERYBODY".
  
Impact

    An attacker could run arbitrary code as the user running PHP.
  
Workaround

    There are several workarounds to this vulnerability:
    Make sure that your temporary directory is not contained in the
    webroot; by default it is located outside the webroot.
    Disable upload rights to all albums for "EVERYBODY"; upload is
    disabled by default.
    Disable debug and dev mode; these settings are disabled by
    default.
    Disable allow_url_fopen in php.ini.
  
');
script_set_attribute(attribute:'solution', value: '
    All Gallery users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=www-apps/gallery-1.4.4_p2"
    # emerge ">=www-apps/gallery-1.4.4_p2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0757.html');
script_set_attribute(attribute: 'see_also', value: 'http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=134&mode=thread&order=0&thold=0');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1466');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-05] Gallery: Arbitrary command execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/gallery", unaffected: make_list("ge 1.4.4_p2"), vulnerable: make_list("lt 1.4.4_p2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
