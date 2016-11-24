
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(41361);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  OpenOffice_org (2009-08-29)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for OpenOffice_org");
 script_set_attribute(attribute: "description", value: "This update of OpenOffice.org fixes potential buffer
overflow in EMF parser code (enhwmf.cxx, emfplus.cxx)
(Thanks to Petr Mladek). Additionally Secunia reported an
integer underflow (CVE-2009-0200) and a buffer overflow
(CVE-2009-0201) that could be triggered while parsing Word
documents.

Also provides the maintenance update to
OpenOffice.org-3.1.1.

Details about all upstream changes can be found at
http://development.openoffice.org/releases/3.1.1.html

The Novell changes are:

------------------------------------------------------------
 ------- Thu Aug 27 18:12:20 CEST 2009 - pmladek@suse.cz

- maintenance update for SLED11 (MaintenanceTracker-25396)
- ooo-build-3.1.1.1 == 3.1.1-rc1 == final

------------------------------------------------------------
 ------- Wed Aug 26 13:28:08 CEST 2009 - pmladek@suse.cz

- updated to the milestone ooo310-m19
- updated ooo-build to version 3.1.1.1 (3.1.1-rc1):
    * Common bits:
	* prevent multiple window resize when maximised (i#104469)
	* save non-English file names with KDE4 dialog (deb#536664)
	* keep locks after saving documents via WebDAV (bnc#464568)
	* KDE detection (bnc#529208)
    * Base bits:
	* UPDATE db record failure (i#104088)
    * Calc bits:
	* multi-range copy-n-paste stuff fix
    * Impress bits:
	* wrong text bounds in Impress (bnc#523603)
    * OOXML bits:
	* data sequence creation in PPTX import (bnc#500175)
    * l10n bits:
	* French translation update
	* Finnish translation update
	* Hungarian translation update
- updated extra localization sources: ga nb nn sl

------------------------------------------------------------
 ------- Tue Aug 18 19:51:59 CEST 2009 - pmladek@suse.cz

- updated to the milestone ooo310-m18
- updated ooo-build to version 3.1.0.99.3 (3.1.1-beta3):
    * speed up::
	* cache fontconfig's pre-match substitution results
   (n#529532)
    * Common bits:
	* saving pictures with preview size (bnc#531221, i#104146)
	* menubar theme support (bnc#526004, bnc#527356, i#103999)
    * Base bits:
	* Table Wizard categories (i#102019)
    * Calc bits:
	* Unicode string in document URI in Edit Links dialog
   (i#104166)
	* several regressions in external references (i#103918)
    * OOXML bits:
	* pivot data PPTX export (bnc#505917)
    * l10n bits:
	* Hungarian translation of About dialog
	* ooo-build.pot update file

------------------------------------------------------------
 ------- Tue Aug  4 22:19:15 CEST 2009 - pmladek@suse.cz

- updated to the milestone ooo310-m17
- updated ooo-build to version 3.1.0.99.2 (3.1.1-beta2):
    * feature:
	* animated border for copied range
	* better modified status icon in statusbar (i#103862)
	* surface shades, custom shapes gradient color (bnc#485637)
    * common bits:
	* squeezed check boxes in sub menus (bnc#523852)
	* show templates installed as extension (bnc#512146)
	* single-point polygons in fontwork crasher (bnc#526342)
    * Calc fixes:
	* sorting when the first row was not 0 (bnc#524215)
	* string cell format during text file import (bnc#523414)
	* non-default max column/row size for range names
   (bnc#522833)
    * Draw:
	* autoshape geometry on model change
	* avoids messing with fontwork glyph polygons (bnc#485637)
    * VBA bits:
	* broken Styles.Add
	* toolbar XLS import
	* broken toolbar import
	* typename issue (bnc#525649)
	* better heuristic for deleted ctrls
	* support for tooltips and separators
	* HTMLSelect activex objects XLS import (bnc#523191)
	* Financial functions (bnc#525633, bnc#525635, bnc#525642,
   bnc#525647)
    * OOXML bits:
	* pivot table XLSX export (bnc#505917)
	* animations PPTX export (bnc#497570)
	* blip luminance PPTX export (bnc#497570)
	* better header/footer DOCX import (bnc#519201)
    * l10n bits:
	* Russian translation update
	* Hungarian translations update
	* translations update by openSUSE community
	* Spanish translation of the autofilter menu (i#103840)
- updated extra localizations sources: bg el mk nb nn sk sl

------------------------------------------------------------
 ------- Thu Jul 23 21:16:24 CEST 2009 - pmladek@suse.cz

- updated to the milestone ooo310-m16
- updated ooo-build to version 3.1.0.99.1 (3.1.1-beta1):
    * features:
	* new unopkg add --link option
	* new -bulk option to convert documents on the command line
    * common bug fixes:
	* updated Graphite font technology stuff
	* avoid sticky state of fullscreen window (i#103145)
    * Calc fixes:
	* XLS import crasher (bnc#520556)
	* scrolling with large selection (n#518426)
	* determine in-line array size more reliably
	* more on row and flags manipulations (n#516406)
	* hyperlink strings XLS import (bnc#521447, i#103520)
	* COUNTIF with external references (bnc#521624, i#102750)
	* absolute path generation for external doc URI (i#103317)
	* clink on hyperlinks behavior in Calc (i#103587, n#523005)
	* document is modified when switching external link
   (i#103598)
     * Impress fixes:
	* no impress layout pane in master page mode (i#73289)
    * Writer fixes:
	* RTF export crash (bnc#462657)
	* lost indentation during DOC import (bnc#518731)
    * VBA bits:
	* ComboBox binding data import in userform
	* create toolbar/menubar in document scope
	* variable as VBA constant (bnc#521820)
	* set Enabled/Disabled to menu item (i#103486)
	* automation objects, automation bridge wrapper
   (bnc#507501)
	* WorkBook.PrecisionAsDisplayed, and
   CommandbarControl.Enabled, support workbook auto_open
   event, builtin toolbar (bnc#520228)
    * OOXML bits:
	* shape map crash
	* action buttons PPTX export (bnc#497570)
	* footnote in a table DOCX import crasher (bnc#518741)
    * l10n bits:
	* ooo-build.pot update
	* Serbian translation update

------------------------------------------------------------
 ------- Mon Jun 29 19:30:31 CEST 2009 - pmladek@suse.cz

- updated to the milestone ooo310-m14
- updated ooo-build to version 3.1.0.98.2 (3.1.1-alpha2):
    * features:
	* Oxygen icons theme for KDE4
	* OOXML export enabled by default
    * general bug fixes:
	* more on the KDE support
	* better KDE3/KDE4 detection
	* selection engine's auto repeat interval (bnc#514395)
	* early startup race in generic vcl plug (i#103148)
	* sticky fullscreen window state for xinerama (bnc#480324)
    * Calc fixes:
	* slow down scrolling interval (n#514395)
	* unsupported encryption XLS import crasher (i#102906)
	* non-scrolling formula reference selection (bnc#512060)
	* more optimization for increased row limit (bnc#514156)
	* chart update problems with Excel documents (bnc#491898)
	* non-initiated reference mode in selection range
   (bnc#512060)
	* selection area before setting autofilter arrows
   (bnc#514164)
	* strip time elements only when fields contains dates
   (i#94695)
	* autofill marker position when expanding selection
   (bnc#514151)
    * Impress fixes:
	* lots fixes of numbering (i#101269)
	* isotropic fit-to-size scale (i#94086)
    * Writer:
	* table shifted left margin DOC export (i#100473)
    * OOXML bits:
	* blank paragraphs DOCX import
	* reduce the number of dummy page styles DOCX import
	* collapsed paragraphs at the end of the sections DOCX
   import
    * VBA bits:
	* load problem for non MSO documents
	* maximum range selection and scrolling
	* Window.Zoom should affect only current sheet
	* fallback to the calling document as active doc
	* property value 'BulletId' could be greater than 255
   (i#103021)
- added OpenOffice_org-branding into Requires also for
  openSUSE-10.3 (bnc#514944)
- changed BuildRequires from OpenOffice_org-help-devel to
  the new OpenOffice_org-help-en-US-devel

------------------------------------------------------------
 ------- Mon Jun 15 21:16:25 CEST 2009 - pmladek@suse.cz

- updated to the milestone ooo310-m13
- updated ooo-build to version 3.1.0.98.1 (3.1.1-alpha1)
    * features:
	* support ooo310-m13
	* KDE4 vcl plugin and file picker
	* initial support for SmartArt import
	* autoplay .pps/.ppsx files (bnc#485645)
	* custom sort in datapilot tables (bnc#443361)
	* DataPilot's custom names ODF import/export (bnc#479062)
	* option to turn off auto number recognition in HTML import
	* sheet options and password ODS import/export
   (i#60305,i#71468)
    * speed up:
	* progress bar during formula calculation (i#102566)
	* cell range selection & cursor placement (bnc#511006)
	* column-wise sorting in Calc (bnc#504827)
	* more on faster sheet switch (bnc#495140)
    * bug fixes:
	* USHORT vs. SCROW or SCCOL (bnc#509768)
	* cursor after drag-n-dropped (bnc#508872)
	* slow page style changing in Calc (n#503482)
	* multi-range copy-n-paste crasher (bnc#509209)
	* rows filtered via autofilter crasher (bnc#495140)
	* merged cell attribute flag corruption (bnc#508867)
	* shifted translations of OOo Calc options (bnc#507643)
	* replace 'Manual Break' with 'Page Break' in Calc's menu
	* Launch language chooser for all HTML import (bnc#506095)
	* show cursor in all panes in split-view mode (bnc#433834)
	* do not move the cursor when making a selection
   (bnc#502717)
	* custom language and number options for CSV import
   (bnc#510168)
	* surface shades, custom shapes gradient color (bnc#485637)
	* misplaced rotated groups in PPT import (bnc#485637)
	* creating tables in Impress (bnc#483951, i#100275)
	* fit to frame text feature crasher (bnc#508621)
	* MM_TEXT map mode support in WMF (bnc#417818)
	* relative size calculation in SVG import
	* crash on quit after DOC import (bnc#505704)
	* fix SDK to actually find the libraries (i#101883)
	* default button in enter password dialog (i#102230)
	* HTML OLE controls as OCX controls DOC import (bnc#485609)
	* duplicit accept/reject menu entries (bnc#249775,i#6191)
    * OOXML bits:
	* prefer odf-converter over native OOXML filters
   (bnc#502173)
	* set flavour to EXC_OUTPUT_XML_2007 in XLSX export
   (bnc#502090)
	* XML_useAutoFormatting XLSX export (bnc#497560)
	* styles XLSX import/export (bnc#497563)
	* row limit in XLSX export (bnc#504623)
	* autoFilter XLSX export (bnc#497559)
	* rotated text PPTX export(bnc#498737)
	* transitions PPTX import (bnc#480243)
	* various PPTX import issues (bnc#377727)
	* text hyperlinks PPTX export (bnc#499124)
	* shapes visibility PPTX import (bnc#480243)
	* paragraph line spacing PPTX export (bnc#498737)
	* shape fill properties PPTX import (i#101563)
	* placeholder text style PPTX import (bnc#479834)
	* subtitle placeholder PPTX import (bnc#480243)
	* text body properties priority in PPTX import (bnc#403402)
	* un-connected connector shapes PPTX export (bnc#499129)
	* hidden slide PPTX import and export (bnc#480229,
   n#499131)
	* header, footer, datetime, pagenumber PPTX import
   (bnc#480243)
	* page break after tables in DOCX import (bnc#478945,
   i#101661)
	* footnote character properties DOCX import (bnc#478972)
	* extra paragraph in DOCX import (bnc#478977)
	* better outline DOCX import (bnc#478583)
    * VBA bits:
	* toolbars import
	* more on the Word support
	* macro execution via VBA API
	* crasher caused by resize event
	* rework use of getCurrentDocument
	* vbadocumentbase::getPath (bnc#507745)
	* add application.quit API (bnc#510003)
	* initial version of new macro resolver
	* checkbox access via VBA API (bnc#507400)
	* vbadocumentbase::getFullName (bnc#507745)
	* active newly added worksheet (bnc#507758)
	* default value control setting (bnc#507748)
	* allow worksheet to be passed as param (bnc#507760)
	* add to support menubar related objects (bnc#508113)
	* code name incorrectly imported for sheet (bnc#507768)
	* userform filter and userform controls visibility
   (i#88878)
	* auto calculation of shift direction for delete
   (bnc#508101)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for OpenOffice_org");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=437666");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=514085");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=514089");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=249775");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=377727");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=403402");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=417818");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=433834");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=443361");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=462657");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=464568");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478583");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478945");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478972");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478977");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=479062");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=479834");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=480229");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=480243");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=480324");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=483951");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=485609");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=485637");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=485645");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=491898");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=495140");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=497559");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=497560");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=497563");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=497570");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=498737");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=499124");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=499129");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=499131");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=500175");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=502090");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=502173");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=502717");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=503482");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=504623");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=504827");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=505704");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=505917");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=506095");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=507400");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=507501");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=507643");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=507745");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=507748");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=507758");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=507760");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=507768");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=508101");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=508113");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=508621");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=508867");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=508872");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=509209");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=509768");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=510003");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=510168");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=511006");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=512060");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=512146");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=514151");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=514156");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=514164");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=514395");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=514944");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=516406");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=518426");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=518731");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=518741");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=519201");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=520228");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=520556");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=521447");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=521624");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=521820");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=522833");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=523005");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=523191");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=523414");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=523603");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=523852");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=524215");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=525633");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=525635");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=525642");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=525647");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=525649");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=526004");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=526342");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=527356");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=529208");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=529532");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=531221");
script_end_attributes();

 script_cve_id("CVE-2009-0200", "CVE-2009-0201");
script_summary(english: "Check for the OpenOffice_org package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"OpenOffice_org-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-LanguageTool-0.9.9-2.1.2", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-LanguageTool-de-0.9.9-2.1.2", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-LanguageTool-en-0.9.9-2.1.2", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-LanguageTool-es-0.9.9-2.1.2", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-LanguageTool-fr-0.9.9-2.1.2", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-LanguageTool-it-0.9.9-2.1.2", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-LanguageTool-nl-0.9.9-2.1.2", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-LanguageTool-pl-0.9.9-2.1.2", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-LanguageTool-sv-0.9.9-2.1.2", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-base-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-base-drivers-postgresql-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-base-extensions-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-calc-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-calc-extensions-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-components-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-draw-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-draw-extensions-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-filters-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-filters-optional-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gnome-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-ar-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-cs-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-da-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-de-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-en-GB-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-en-US-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-en-US-devel-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-es-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-fr-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-gu-IN-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-hi-IN-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-hu-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-it-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-ja-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-ko-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-nl-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-pl-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-pt-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-pt-BR-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-ru-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-sv-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-zh-CN-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-help-zh-TW-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-icon-themes-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-impress-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-impress-extensions-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-kde-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-af-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-ar-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-ca-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-cs-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-da-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-de-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-el-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-en-GB-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-es-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-extras-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-fi-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-fr-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-gu-IN-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-hi-IN-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-hu-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-it-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-ja-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-ko-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-nb-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-nl-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-nn-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-pl-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-pt-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-pt-BR-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-ru-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-sk-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-sv-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-xh-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-zh-CN-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-zh-TW-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-l10n-zu-3.1.1.1-0.1.1", release:"SLED11", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-libs-core-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-libs-extern-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-libs-gui-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-mailmerge-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-math-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-mono-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-officebean-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pyuno-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ure-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-writer-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-writer-extensions-3.1.1.1-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
