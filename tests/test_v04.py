import httpx
import pytest
from app import history
from app.main import app
from app.reports import build_pdf

@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(history, 'DB_PATH', tmp_path / 'scans.sqlite3')


def sample_report(score=80):
    return {'url':'http://localhost:8000','score':score,'risk':'Low','status_code':200,
            'checks':[{'name':'CSP','status':'Needs attention','severity':'High','evidence':'<missing> & absent','recommendation':'Set CSP'},
                      {'name':'MIME','status':'Passed','severity':'Informational','evidence':'nosniff','recommendation':None}],
            'summary':{'passed':1,'failed':1,'not_applicable':0},'note':'Passive configuration assessment.'}

@pytest.mark.asyncio
async def test_analytics_and_pdf(isolated_db):
    first=history.save_scan(sample_report(80))
    history.save_scan(sample_report(100))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://localhost:8000') as client:
        response=await client.get('/api/analytics')
        assert response.status_code == 200
        data=response.json()
        assert data['total_scans']==2
        assert data['unique_targets']==1
        assert data['average_score']==90
        assert data['severity']['High']==2
        pdf=await client.get(f"/api/history/{first['id']}/report.pdf")
        assert pdf.status_code==200
        assert pdf.content.startswith(b'%PDF-')
        assert pdf.headers['content-type']=='application/pdf'
        assert 'attachment' in pdf.headers['content-disposition']
        missing=await client.get('/api/history/does-not-exist/report.pdf')
        assert missing.status_code==404

@pytest.mark.asyncio
async def test_empty_analytics(isolated_db):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://localhost:8000') as client:
        data=(await client.get('/api/analytics')).json()
        assert data['total_scans']==0
        assert data['average_score'] is None
        assert (await client.get('/api/analytics?limit=501')).status_code==422
