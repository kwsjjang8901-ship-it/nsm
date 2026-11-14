##! ============================================================================
##! AI 서비스 공통 — 생성형 AI 서비스·LLM API 도메인 목록과 판정 함수
##!
##!   - 33 AI 위협 탐지(업로드·서버의 AI API 호출)와 07·30 비커닝(근거의 ai_service 표시)이 함께 쓴다.
##!   - 이름은 등록 도메인 또는 서비스 호스트 단위. 하위 도메인까지 맞춘다(api.openai.com ⊂ openai.com).
##! ============================================================================

module NSM;

export {
    ## 생성형 AI 대화 서비스와 LLM API 도메인(소문자). 고객이 쓰는 사내·국내 서비스는 += 로 더한다.
    const ai_service_domains: set[string] = {
        "openai.com", "chatgpt.com", "oaiusercontent.com",            # ChatGPT·OpenAI API
        "anthropic.com", "claude.ai",                                  # Claude·Anthropic API
        "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
        "copilot.microsoft.com",
        "deepseek.com", "mistral.ai", "perplexity.ai", "x.ai", "grok.com",
        "huggingface.co", "cohere.com", "cohere.ai", "groq.com", "together.xyz", "together.ai",
        "openrouter.ai", "poe.com", "character.ai",
        "moonshot.cn", "chat.qwen.ai", "dashscope.aliyuncs.com",
        "wrtn.ai", "clova-x.naver.com",
    } &redef;

    ## name(SNI·HTTP Host·DNS 질의)이 AI 서비스면 맞은 목록 항목, 아니면 "".
    global ai_service_match: function(name: string): string;

    ## 연결의 서비스 이름(SNI 우선, 없으면 HTTP Host). 없으면 "".
    global conn_service_name: function(c: connection): string;
}

function ai_service_match(name: string): string
    {
    if ( name == "" )
        return "";
    local n = to_lower(name);
    if ( |n| > 0 && n[|n| - 1:] == "." )
        n = n[:|n| - 1];
    # 접미사를 한 단계씩 줄여 가며 목록에서 찾는다(목록을 다 훑지 않음).
    local labels = split_string(n, /\./);
    local i = 0;
    while ( i < |labels| )
        {
        local cand = join_string_vec(labels[i:], ".");
        if ( cand in ai_service_domains )
            return cand;
        ++i;
        }
    return "";
    }

function conn_service_name(c: connection): string
    {
    if ( c?$ssl && c$ssl?$server_name )
        return c$ssl$server_name;
    if ( c?$http && c$http?$host )
        return c$http$host;
    return "";
    }
