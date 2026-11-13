# @TEST-DOC: 33 AI 관련 위협 — chat.openai.com 으로 1시간 안 12MB 업로드(.2.60) 탐지 / 작은 API 요청(.2.61)·AI 아닌 사이트 30MB(.2.62) 미탐. 서버로 학습된 DB 서버(.2.70, 1433 응답)·KDC(.0.10, Kerberos 응답)의 LLM API 접속 탐지 / PC(.2.72)의 같은 접속·서버의 일반 사이트 접속 미탐. AI 인프라(.2.80) 관리 API: Ray 작업 제출·Ollama pull·TorchServe URL 등록·Jupyter 터미널·MLflow 경로 조작·외부의 Ray 작업 제출 탐지 / Ray 작업 조회·Ollama generate 미탐
# @TEST-EXEC: zeek -C -r $TRACES/ai_threats.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::AI_Service_Upload src=10.0.2.60
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::AI_Service_Upload src=10.0.2.61
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::AI_Service_Upload src=10.0.2.62
# @TEST-EXEC: grep -q 'service=openai.com upload_mb=12.0 conns=3' notice.log
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::AI_API_From_Server src=10.0.2.70
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::AI_API_From_Server src=10.0.0.10
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::AI_API_From_Server src=10.0.2.72
# @TEST-EXEC: assert-rows notice.log eq 2 note=NSM::AI_API_From_Server
# @TEST-EXEC: assert-rows notice.log eq 6 note=NSM::AI_Service_Exploit dst=10.0.2.80
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::AI_Service_Exploit src=10.0.2.81
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::AI_Service_Exploit src=10.0.2.82
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::AI_Service_Exploit src=93.184.215.170 'sub=api=ray_job_submit source=external'
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::AI_Service_Exploit operation=ai_service_mlflow_path_traversal
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::AI_Service_Exploit operation=ai_service_torchserve_register
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::AI_Service_Exploit operation=ai_service_jupyter_terminal
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Exfiltration.AiServiceUpload
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 diagnosis=NSM.C2.AiApiFromServer
# @TEST-EXEC: assert-rows nsm_detection.log eq 6 diagnosis=NSM.WebAttack.AiServiceExploit
# @TEST-EXEC: assert-evidence-join NSM::AI_Service_Upload
# @TEST-EXEC: assert-evidence-join NSM::AI_API_From_Server
# @TEST-EXEC: assert-evidence-join NSM::AI_Service_Exploit
