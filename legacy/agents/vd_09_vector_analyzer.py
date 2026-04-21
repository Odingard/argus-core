"""
agents/vd_09_vector_analyzer.py
VD-09 — Vector Intelligence Agent

Hunts RAG (Retrieval-Augmented Generation) and Vector-Database poisoning vulnerabilities.

Techniques (3):
  VD-T1  RAG_PROMPT_INJECTION — find vectors where untrusted retrieved docs inject prompts
  VD-T2  EMBEDDING_POISONING  — find unrestricted write access to vector databases
  VD-T3  VECTOR_SQL_INJECTION — identify improper sanitization in vector metadata filters
"""
from __future__ import annotations

import json
import os
import re

from argus.agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
GRAY  = "\033[90m"
RESET = "\033[0m"


class VectorPoisoningAgent(BaseAgent):
    AGENT_ID   = "VD-09"
    AGENT_NAME = "Vector Intelligence Agent"
    VULN_CLASS = "RAG_POISONING"
    TECHNIQUES = ["VD-T1", "VD-T2", "VD-T3"]
    MAAC_PHASES = [4]  # Memory Corruption (RAG / vector-store poisoning)

    # Patterns looking for vector DB usage or retrieval
    RAG_RETRIEVE_PATTERNS = [
        r'similarity_search', r'vectorstore', r'faiss', r'chromadb', r'pinecone',
        r'qdrant', r'weaviate', r'milvus', r'retriever'
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "VD-T1": self._t1_rag_prompt_injection,
            "VD-T2": self._t2_embedding_poisoning,
            "VD-T3": self._t3_vector_metadata_filter,
        }

    def run(self, target: str, repo_path: str, output_dir: str) -> list[AgentFinding]:
        self._print_header(target)
        files = self._discover_files(repo_path)
        print(f"  Files     : {len(files)}\n")

        for tech_id, fn in self.technique_library.items():
            print(f"  {BLUE}[{tech_id}]{RESET} {fn.__doc__ or tech_id}")
            fn(files, repo_path)

        self.save_history(target, output_dir)
        self.save_findings(output_dir)
        print(f"\n  {BOLD}{self.AGENT_ID} complete{RESET} — {len(self.findings)} findings")
        return self.findings

    def _t1_rag_prompt_injection(self, files: list[str], repo_path: str):
        """Find vectors where untrusted retrieved docs inject prompts"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code: continue
            
            if not any(re.search(p, code, re.IGNORECASE) for p in self.RAG_RETRIEVE_PATTERNS):
                continue
                
            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(f"""Analyze this code for indirect prompt injection via RAG retrieval.
FILE: {rel}
CODE snippet: {code[:2000]}

Identify if retrieved documents are passed directly into an LLM context without sandboxing or sanitization.
Return JSON only: {{"findings": [{{"severity": "HIGH", "title": "title", "description": "desc", "remediation": "fix"}}]}}""")
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(self._fid(rel+f["title"]), self.AGENT_ID, self.VULN_CLASS, f["severity"], f["title"], rel, "VD-T1", f["description"], "Poison vector DB -> retrieve -> injection", None, None, None, f.get("remediation")))
            except (json.JSONDecodeError, KeyError, Exception) as e:
                if self.verbose:
                    print(f"  [VD-T1] {rel}: {type(e).__name__}: {e}")

    def _t2_embedding_poisoning(self, files: list[str], repo_path: str):
        """Find unrestricted write access to vector databases"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code: continue
            if "add_documents" not in code and "upsert" not in code: continue
            
            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(f"""Analyze this code for Unrestricted Embedding/Vector DB Writes.
FILE: {rel}
CODE: {code[:2000]}

Does this code allow untrusted users to insert documents into the vector datastore without verification?
Return JSON: {{"findings": [{{"severity": "HIGH", "title": "title", "description": "desc", "remediation": "fix"}}]}}""")
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(self._fid(rel+f["title"]), self.AGENT_ID, self.VULN_CLASS, f["severity"], f["title"], rel, "VD-T2", f["description"], "Untrusted write -> permanent poisoning", None, None, None, f.get("remediation")))
            except (json.JSONDecodeError, KeyError, Exception) as e:
                if self.verbose:
                    print(f"  [VD-T2] {rel}: {type(e).__name__}: {e}")

    def _t3_vector_metadata_filter(self, files: list[str], repo_path: str):
        """Identify improper sanitization in vector metadata filters"""
        filter_patterns = [
            r'metadata_filter', r'where\s*=', r'filter\s*=',
            r'\.query\(.*filter', r'search.*metadata',
        ]
        sanitize_patterns = [
            r'sanitiz', r'escap', r'parameteriz', r'validate.*filter',
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            has_filter = any(
                re.search(p, code, re.IGNORECASE) for p in filter_patterns
            )
            if not has_filter:
                continue
            has_sanitize = any(
                re.search(p, code, re.IGNORECASE) for p in sanitize_patterns
            )
            if has_sanitize:
                continue
            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "vector_metadata_filter"),
                self.AGENT_ID, self.VULN_CLASS, "MEDIUM",
                f"Unsanitized vector metadata filter in {rel}",
                rel, "VD-T3",
                "Vector database metadata filters accept user-controlled input "
                "without sanitization. An attacker could manipulate filter "
                "expressions to access unauthorized documents or bypass "
                "tenant isolation.",
                "Inject malicious metadata filter to bypass access controls",
                None, None, None,
                "Validate and sanitize all metadata filter inputs. Use "
                "parameterized queries or an allowlist of filter fields.",
            ))

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = VectorPoisoningAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
