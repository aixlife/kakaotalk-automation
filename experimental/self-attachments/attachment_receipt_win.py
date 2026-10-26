"""Read back only the two harmless QA attachments from the verified MemoChat.

Attachment URLs, keys, tokens, raw attachment JSON and user IDs are never emitted.
"""
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
import urllib.request

from selfqa_config import ROOT, SOURCE_ROOT, READER_ROOT, PYTHON


def qa_row_candidate(request, message_type, message, attachment):
    if message_type == 18:
        return message == request['file_name']
    if message_type != 2 or request['kind'] != 'image':
        return False
    if request.get('require_no_ui'):
        return (type(attachment.get('s')) is int
                and attachment.get('s') == request.get('file_bytes')
                and attachment.get('w') == request.get('image_width')
                and attachment.get('h') == request.get('image_height'))
    return True  # Historical preview-approved QA; final SHA is still required.


def inspect(rid, download=False):
    from room_reader import Reader, text
    assert re.fullmatch('[a-f0-9]{32}', rid)
    request = json.loads((ROOT / ('attachment-send-' + rid + '.json')).read_text(encoding='utf-8-sig'))
    assert request['destination'] == 'SELF_CHAT_ONLY'
    source_path = ROOT / ('attachment-send-' + rid + '-execute-self.json')
    source = json.loads(source_path.read_text(encoding='utf-8-sig'))['result']
    if request.get('require_no_ui'):
        ledger = json.loads((ROOT / ('attachment-send-' + rid + '-ledger.json')).read_text(encoding='utf-8-sig'))
        assert (ledger.get('request_id') == rid and ledger.get('file_sha256') == request['file_sha256']
                and ledger.get('file_name') == request['file_name'] and ledger.get('kind') == request['kind']), 'SEND_LEDGER_MISMATCH'
        assert ledger.get('preflight_self_sha256') == hashlib.sha256(source_path.read_bytes()).hexdigest(), 'BASELINE_LEDGER_MISMATCH'
    assert source['room']['type'] == 'MemoChat' and source['messages']
    assert all(m['author_is_self'] for m in source['messages'])
    authors = {int(m['author_id']) for m in source['messages']}
    assert len(authors) == 1
    baseline = max(int(m['log_id']) for m in source['messages'])
    reader = Reader()
    result = {'status': 'RECEIPT_NOT_FOUND', 'request_id': rid,
              'kind': request['kind'], 'fixture_name': request['file_name'],
              'url_saved': False, 'key_saved': False, 'raw_attachment_saved': False,
              'input_calls': 0, 'clipboard_calls': 0, 'settings_changed': False,
              'source': 'VALIDATED_READ_ONLY_MEMOCHAT_SNAPSHOT'}
    metadata = None
    con = None
    try:
        result['app_private_before'] = reader.guard()
        metadata = reader.database(reader.data / 'chatListInfo.edb')
        memos = metadata.execute("SELECT chatId FROM chatRoomList WHERE type='MemoChat' LIMIT 2").fetchall()
        assert len(memos) == 1 and str(memos[0]['chatId']) == source['room']['chat_id'], 'SELF_IDENTITY_CHANGED'
        con = reader.database(reader.data / ('chatLogs_' + str(int(memos[0]['chatId'])) + '.edb'))
        columns = [row[1] for row in con.execute('PRAGMA table_info(chatLogs)')]
        result['available_columns'] = columns
        ident = next((name for name in ('id', 'logId', '_id') if name in columns), None)
        attach = next((name for name in ('attachment', 'attachement') if name in columns), None)
        if not ident or not attach or not {'authorId', 'message', 'type'} <= set(columns):
            result['status'] = 'ATTACHMENT_SCHEMA_NOT_SUPPORTED'
            return result
        types = (18,) if request['kind'] == 'file' else (2, 18)
        exact = ' AND message=?' if request['kind'] == 'file' else ''
        params = (baseline, next(iter(authors)), *types)
        if exact: params += (request['file_name'],)
        found = con.execute('SELECT ' + ident + ' AS id,authorId,type,message,' + attach + ' AS attachment FROM chatLogs WHERE ' + ident + '>? AND authorId=? AND type IN (' + ','.join('?' for _ in types) + ')' + exact + ' ORDER BY ' + ident + ' LIMIT 16', params).fetchall()
        if len(found) == 16:
            result['status'] = 'RECEIPT_QUERY_BOUND_OR_AMBIGUOUS'
            return result
        rows = []
        for candidate in found:
            raw = text(candidate['attachment'])
            if len(raw) > 32768: continue
            try: meta = json.loads(raw)
            except ValueError: continue
            if isinstance(meta, dict) and qa_row_candidate(request, candidate['type'], text(candidate['message']), meta):
                rows.append(candidate)
        result['matching_rows'] = len(rows)
        if len(rows) != 1:
            return result
        row = rows[0]
        assert 0 < row['id'] < 2 ** 63
        raw = text(row['attachment'])
        assert len(raw) <= 32768
        attachment = json.loads(raw)
        assert isinstance(attachment, dict)
        result.update(status='QA_ATTACHMENT_ROW_OBSERVED', type=row['type'],
                      author_is_self=True, new_after_preflight=True,
                      positive_server_style_log_id=True,
                      filename_exact=text(row['message']) == request['file_name'],
                      attachment_keys=sorted(attachment))
        if request['kind'] == 'image':
            result['image_delivery_mode'] = 'PHOTO_BUBBLE' if row['type'] == 2 else 'PNG_FILE_ATTACHMENT'
        for key in ('s', 'size', 'w', 'h', 'width', 'height'):
            value = attachment.get(key)
            if type(value) is int and 0 <= value < 100000000:
                result[key] = value
        hosts = []
        for key in ('url', 'thumbnailUrl', 'thumbnail_url', 'thumbnail', 'originalUrl'):
            value = attachment.get(key)
            if isinstance(value, str) and value.startswith('https://'):
                parsed = urlsplit(value)
                hosts.append({'field': key, 'host': parsed.hostname, 'https': True})
        result['attachment_url_hosts'] = hosts
        if download:
            url = attachment.get('url')
            assert isinstance(url, str) and urlsplit(url).scheme == 'https'
            assert urlsplit(url).hostname == 'talk.kakaocdn.net', 'UNREVIEWED_DOWNLOAD_HOST'

            class OwnCdnRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    parsed = urlsplit(newurl)
                    assert parsed.scheme == 'https' and parsed.hostname == 'talk.kakaocdn.net', 'UNREVIEWED_REDIRECT_HOST'
                    return super().redirect_request(req, fp, code, msg, headers, newurl)

            opener = urllib.request.build_opener(OwnCdnRedirect())
            with opener.open(url, timeout=6) as response:
                assert response.status == 200, 'DOWNLOAD_NOT_OK'
                declared = response.headers.get('Content-Length')
                assert declared is None or int(declared) <= 262144, 'DOWNLOAD_SIZE_LIMIT'
                received = response.read(262145)
            assert 0 < len(received) <= 262144, 'DOWNLOAD_SIZE_LIMIT'
            digest = hashlib.sha256(received).hexdigest()
            result.update(download_http_status=200, downloaded_bytes=len(received),
                          received_sha256=digest, original_sha256_matches=digest == request['file_sha256'])
            if digest == request['file_sha256']:
                suffix = '.txt' if request['kind'] == 'file' else '.png'
                destination = ROOT / ('attachment-received-' + rid + suffix)
                if destination.exists():
                    assert destination.read_bytes() == received
                else:
                    with destination.open('xb') as stream:
                        stream.write(received)
                result['status'] = ('PNG_FILE_RECEIVED_NOT_PHOTO' if request['kind'] == 'image' and row['type'] != 2
                                    else 'QA_ATTACHMENT_DOWNLOADED_HASH_EXACT')
                result['received_qa_copy_name'] = destination.name
            del received, url
        result['app_private_after'] = reader.guard()
        return result
    finally:
        if con:
            con.close()
        if metadata:
            metadata.close()
        reader.close()


if __name__ == '__main__':
    assert len(sys.argv) in (2, 3) and (len(sys.argv) == 2 or sys.argv[2] == '--download-qa')
    try:
        output = inspect(sys.argv[1], len(sys.argv) == 3)
    except Exception as error:
        output = {'status': 'BLOCKED', 'error_type': type(error).__name__,
                  'reason': str(error) if isinstance(error, (AssertionError, RuntimeError)) else 'DETAILS_WITHHELD',
                  'url_saved': False, 'key_saved': False}
    print(json.dumps(output), flush=True)
