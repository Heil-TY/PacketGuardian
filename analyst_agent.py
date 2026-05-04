import requests
import re
import json
import datetime

def load_researcher_data(filepath="researcher_output_clean.json"):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data[0] if data else None

def generate_analyst_prompt(research_data):
    threat = research_data.get("top_threat", {})
    indicators = research_data.get("indicators", {})
    evidence_list = "\n".join([f"- {e}" for e in research_data.get("evidence", [])])
    reasoning = research_data.get("reasoning", "")
    
    prompt = f"""
[System Role]
You are a Senior Incident Responder. Draft a rigorous, defense-oriented security report based on the provided structured evidence.

[Event Context]
- Risk Level: {research_data.get('risk_level', 'UNKNOWN').upper()}
- MITRE ATT&CK: {threat.get('id', 'N/A')} - {threat.get('name', 'N/A')}
- Attack Stage: {threat.get('attack_stage', 'N/A')}
- Engine Reasoning: {reasoning}

[Key Evidence Detected]
{evidence_list}

[Strict Rules]
1. Evidence Fidelity: You MUST explicitly cite items from [Key Evidence Detected]. Zero hallucination.
2. Cross-Validation: Evaluate whether the evidence indicates a successful breach or a mere probe based on the attack stage.

[Task]
Generate a Markdown report strictly using these 4 sections:

1. Executive Summary: 1-2 sentences summarizing the core threat.
2. Attack Behavior Analysis: Analyze tactical intent and explain the severity using the mapped MITRE technique.
3. Evidence Chain: Detail the supporting facts by directly quoting the extracted evidence to ensure traceability.
4. Remediation & Mitigation: Provide 3 actionable, protocol-specific defense recommendations.
"""
    return prompt.strip()

def call_llm(prompt):
    print("Connecting to the local Ollama model for deep inference...")
    
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "llama3", 
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2  # 降低温度值，让模型在出具安全报告时更加严谨、减少幻觉
        }
    }
    
    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status() # 检查是否发生 HTTP 错误
        result = response.json()
        return result.get("response", "").strip()
    except requests.exceptions.RequestException as e:
        error_msg = f"The local large model call failed. Please check if Ollama is running in the background. Error message: {e}"
        print(error_msg)
        return error_msg
    
def verify_evidence(report_content, research_data):
    """
    Neural-Symbolic Verification
    Prevents model hallucinations by extracting key evidence enclosed in backticks (` `) 
    from the LLM report and matching it against the underlying JSON data.
    """
    print("Initiating automated forensic verification. Cross-referencing evidence features...")
    
    extracted_quotes = set(re.findall(r'`([^`]+)`', report_content))
    
    ground_truth_text = json.dumps(research_data, ensure_ascii=False).lower()
    
    hallucinations = []
    
    for quote in extracted_quotes:
        if len(quote) <= 3 or quote.lower() in ["high", "medium", "low", "info"]:
            continue
            
        if quote.lower() not in ground_truth_text:
            hallucinations.append(quote)
            
    if hallucinations:
        warning_banner = "> [Automated Forensics Warning - Potential AI Hallucination Detected]\n"
        warning_banner += "> The following evidence artifacts cited in the report lack exact matches in the raw PCAP parsing logs. Manual review is required:\n"
        for h in hallucinations:
            warning_banner += f"> - `{h}`\n"
        warning_banner += "\n"
        
        report_content = report_content.replace("### Evidence Chain", warning_banner + "### Evidence Chain")
        print(f"Warning: {len(hallucinations)} potential hallucination(s) detected. Warning banner injected into the report.")
    else:
        print("Verification passed: All cited evidence perfectly aligns with the underlying traffic ground truth.")
        
    return report_content

def generate_final_report():
    try:
        research_data = load_researcher_data()
    except Exception as e:
        print(f"Error loading research data: {e}")
        return

    if not research_data:
        print("No valid research data found. Aborting analysis.")
        return

    prompt = generate_analyst_prompt(research_data)
    final_report = call_llm(prompt)

    verified_report = verify_evidence(final_report, research_data)

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f"Incident_Report_{timestamp}.md"
    
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(verified_report)
    
    print(f"Analysis complete. Report successfully saved to: {report_filename}")

if __name__ == "__main__":
    generate_final_report()