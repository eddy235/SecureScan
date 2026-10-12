"""Local-only, bounded PDF report rendering."""
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from xml.sax.saxutils import escape


def build_pdf(report):
    stream=BytesIO()
    doc=SimpleDocTemplate(stream,pagesize=A4,rightMargin=20*mm,leftMargin=20*mm,topMargin=18*mm,bottomMargin=18*mm)
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='ReportTitle',parent=styles['Title'],textColor=colors.HexColor('#173456'),fontSize=22,spaceAfter=10))
    styles.add(ParagraphStyle(name='SmallMuted',parent=styles['Normal'],fontSize=9,textColor=colors.HexColor('#546479'),leading=13))
    styles.add(ParagraphStyle(name='Finding',parent=styles['Heading3'],fontSize=11,spaceBefore=9,spaceAfter=4,textColor=colors.HexColor('#173456')))
    story=[Paragraph('SECURESCAN / SECURITY ASSESSMENT',styles['ReportTitle'])]
    for label, value in [('Target',report.get('url','')),('Scanned (UTC)',report.get('scanned_at','')),('Configuration score',f"{report.get('score','N/A')} / 100"),('Reported risk',report.get('risk','N/A'))]:
        story.append(Paragraph(f'<b>{escape(label)}:</b> {escape(str(value))}',styles['Normal']))
        story.append(Spacer(1,3*mm))
    story.extend([Spacer(1,3*mm),Paragraph('Executive summary',styles['Heading2']),Paragraph(escape(report.get('note','This report is a passive configuration review, not a penetration test.')),styles['SmallMuted']),Spacer(1,5*mm)])
    summary=report.get('summary',{})
    data=[['Passed','Needs attention','Not applicable'],[str(summary.get('passed',0)),str(summary.get('failed',0)),str(summary.get('not_applicable',0))]]
    table=Table(data,colWidths=[52*mm]*3)
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#18314d')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('ALIGN',(0,0),(-1,-1),'CENTER'),('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#bdccd9')),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),9)]))
    story.extend([table,Spacer(1,5*mm),Paragraph('Detailed findings',styles['Heading2'])])
    for item in report.get('checks',[]):
        detail=[Paragraph(escape(item.get('name','Unnamed check')),styles['Finding']),Paragraph(f"<b>Status:</b> {escape(str(item.get('status','Unknown')))} &nbsp; <b>Severity:</b> {escape(str(item.get('severity','Unspecified')))}",styles['SmallMuted'])]
        for key,title in [('evidence','Evidence'),('recommendation','Recommendation')]:
            if item.get(key): detail.append(Paragraph(f'<b>{title}:</b> {escape(str(item[key]))}',styles['SmallMuted']))
        story.append(KeepTogether(detail))
    story.extend([Spacer(1,7*mm),Paragraph('Scope and limitations',styles['Heading2']),Paragraph('This report reflects observable response configurations only. Passing checks do not guarantee application security. Assess only systems you are authorized to test.',styles['SmallMuted'])])
    doc.build(story)
    return stream.getvalue()
