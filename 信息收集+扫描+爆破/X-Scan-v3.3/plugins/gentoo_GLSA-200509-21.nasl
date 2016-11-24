# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-21.xml
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
 script_id(19820);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200509-21");
 script_cve_id("CVE-2005-3069");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200509-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200509-21
(Hylafax: Insecure temporary file creation in xferfaxstats script)


    Javier Fernandez-Sanguino has discovered that xferfaxstats cron script
    supplied by Hylafax insecurely creates temporary files with predictable
    filenames.
  
Impact

    A local attacker could create symbolic links in the temporary file
    directory, pointing to a valid file somewhere on the filesystem. When
    the xferfaxstats script of Hylafax is executed, this would result in
    the file being overwritten with the rights of the user running the
    script, which typically is the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Hylafax users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-misc/hylafax
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=329384');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3069');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200509-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200509-21] Hylafax: Insecure temporary file creation in xferfaxstats script');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Hylafax: Insecure temporary file creation in xferfaxstats script');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/hylafax", unaffected: make_list("rge 4.2.0-r3", "rge 4.2.1-r2", "ge 4.2.2"), vulnerable: make_list("lt 4.2.2")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
