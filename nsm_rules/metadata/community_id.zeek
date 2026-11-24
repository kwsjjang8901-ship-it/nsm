##! ============================================================================
##! Community ID — docs/SURICATA_INTEGRATION_DESIGN.md 3.3절, SRS_METADATA_EXPORT 5.1절
##!
##!   Manager 가 다른 제품의 이벤트(Suricata 경보 등)를 이 센서의 연결 기록과 연결 단위로 잇게
##!   연결에 Community ID v1(base64)을 붙인다.
##!     - conn: Zeek policy/protocols/conn/community-id-logging(conn.log 의 community_id).
##!       conn 은 Manager 로 요약(flow_summary)만 가므로, 원본 conn.log 를 남기는 센서(T2)에서 쓴다.
##!     - 연결 단위 선별 전송 로그(kerberos·ntlm·smb_mapping·smb_files·dce_rpc·rdp·ssh·ssl·http):
##!       레코드에 community_id 를 더하고 기록 직전(Log::log_stream_policy)에 채운다.
##!       선별 전송 필드 목록(meta_export_streams)에 들어 있어 Manager 로 간다.
##!   seed 는 NSM::community_id_seed(근거 evidence.log 의 community_id 와 같은 값)를 쓴다.
##!   Suricata 의 community-id-seed 도 같아야 한다.
##! ============================================================================

@load base/protocols/krb
@load base/protocols/ntlm
@load base/protocols/smb
@load base/protocols/dce-rpc
@load base/protocols/rdp
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/http
@load policy/protocols/conn/community-id-logging
@load ../detections/evidence_log   # community_id_seed

module NSM;

export {
    redef record KRB::Info      += { community_id: string &optional &log; };
    redef record NTLM::Info     += { community_id: string &optional &log; };
    redef record SMB::TreeInfo  += { community_id: string &optional &log; };
    redef record SMB::FileInfo  += { community_id: string &optional &log; };
    redef record DCE_RPC::Info  += { community_id: string &optional &log; };
    redef record RDP::Info      += { community_id: string &optional &log; };
    redef record SSH::Info      += { community_id: string &optional &log; };
    redef record SSL::Info      += { community_id: string &optional &log; };
    redef record HTTP::Info     += { community_id: string &optional &log; };
}

# conn 의 Community ID(Zeek 스크립트)도 같은 seed 를 쓰게 맞춘다
event zeek_init() &priority=10
    {
    if ( CommunityID::seed != community_id_seed )
        Option::set("CommunityID::seed", community_id_seed);
    }

function cid_of(id: conn_id): string
    {
    return community_id_v1(id, community_id_seed);
    }

# 기록 직전(모든 필터보다 먼저) 한 번 채운다. 원본 로그(T2)와 선별 전송 로그에 같은 값이 남는다.
hook Log::log_stream_policy(rec: any, id: Log::ID) &priority=10
    {
    if ( rec is SSL::Info )
        {
        local sl = rec as SSL::Info;
        if ( ! sl?$community_id ) sl$community_id = cid_of(sl$id);
        }
    else if ( rec is HTTP::Info )
        {
        local hp = rec as HTTP::Info;
        if ( ! hp?$community_id ) hp$community_id = cid_of(hp$id);
        }
    else if ( rec is KRB::Info )
        {
        local kr = rec as KRB::Info;
        if ( ! kr?$community_id ) kr$community_id = cid_of(kr$id);
        }
    else if ( rec is NTLM::Info )
        {
        local nt = rec as NTLM::Info;
        if ( ! nt?$community_id ) nt$community_id = cid_of(nt$id);
        }
    else if ( rec is SMB::TreeInfo )
        {
        local tr = rec as SMB::TreeInfo;
        if ( ! tr?$community_id ) tr$community_id = cid_of(tr$id);
        }
    else if ( rec is SMB::FileInfo )
        {
        local fi = rec as SMB::FileInfo;
        if ( ! fi?$community_id ) fi$community_id = cid_of(fi$id);
        }
    else if ( rec is DCE_RPC::Info )
        {
        local dr = rec as DCE_RPC::Info;
        if ( ! dr?$community_id ) dr$community_id = cid_of(dr$id);
        }
    else if ( rec is RDP::Info )
        {
        local rd = rec as RDP::Info;
        if ( ! rd?$community_id ) rd$community_id = cid_of(rd$id);
        }
    else if ( rec is SSH::Info )
        {
        local sh = rec as SSH::Info;
        if ( ! sh?$community_id ) sh$community_id = cid_of(sh$id);
        }
    }
