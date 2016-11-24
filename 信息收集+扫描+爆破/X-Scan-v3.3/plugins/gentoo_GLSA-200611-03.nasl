# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-03.xml
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
 script_id(23668);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-03");
 script_cve_id("CVE-2006-5379");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-03
(NVIDIA binary graphics driver: Privilege escalation vulnerability)


    Rapid7 reported a boundary error in the NVIDIA binary graphics driver
    that leads to a buffer overflow in the accelerated rendering
    functionality.
  
Impact

    An X client could trigger the buffer overflow with a maliciously
    crafted series of glyphs. A remote attacker could also entice a user to
    open a specially crafted web page, document or X client that will
    trigger the buffer overflow. This could result in the execution of
    arbitrary code with root privileges or at least in the crash of the X
    server.
  
Workaround

    Disable the accelerated rendering functionality in the Device section
    of xorg.conf :
    Option      "RenderAccel" "false"
  
');
script_set_attribute(attribute:'solution', value: '
    NVIDIA binary graphics driver users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-drivers/nvidia-drivers-1.0.8776"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5379');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-03] NVIDIA binary graphics driver: Privilege escalation vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NVIDIA binary graphics driver: Privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-drivers/nvidia-drivers", unaffected: make_list("ge 1.0.8776", "lt 1.0.8762"), vulnerable: make_list("lt 1.0.8776")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
