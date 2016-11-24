# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200402-04.xml
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
 script_id(14448);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200402-04");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200402-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200402-04
(Gallery 1.4.1 and below remote exploit vulnerability)


    Starting in the 1.3.1 release, Gallery includes code to simulate the behaviour
    of the PHP \'register_globals\' variable in environments where that setting
    is disabled.  It is simulated by extracting the values of the various
    $HTTP_ global variables into the global namespace.
  
Impact

    A crafted URL such as
    http://example.com/gallery/init.php?HTTP_POST_VARS=xxx  causes the
    \'register_globals\' simulation code to overwrite the $HTTP_POST_VARS which,
    when it is extracted, will deliver the given payload. If the
    payload compromises $GALLERY_BASEDIR then the malicious user can perform a
    PHP injection exploit and gain remote access to the webserver with PHP
    user UID access rights.
  
Workaround

    The workaround for the vulnerability is to replace init.php and
    setup/init.php with the files in the following ZIP file:
    http://prdownloads.sourceforge.net/gallery/patch_1.4.1-to-1.4.1-pl1.zip?download
  
');
script_set_attribute(attribute:'solution', value: '
    All users are encouraged to upgrade their gallery installation:
    # emerge sync
    # emerge -p ">=www-apps/gallery-1.4.1_p1"
    # emerge ">=www-apps/gallery-1.4.1_p1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200402-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200402-04] Gallery 1.4.1 and below remote exploit vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery 1.4.1 and below remote exploit vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/gallery", unaffected: make_list("ge 1.4.1_p1"), vulnerable: make_list("lt 1.4.1_p1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
