# AIOps Platform - Project Overview & README

## Executive Summary

This project is a locally deployed AIOps platform built on Kubernetes
(Kind) that combines observability, AI-assisted root cause analysis, and
retrieval-augmented generation (RAG). It integrates Prometheus, Grafana,
Loki, Promtail, Ollama, Qdrant, and LangGraph-style agents to
investigate incidents and generate reports.

## Business Problem

Modern Kubernetes environments generate thousands of metrics, logs, and
alerts. Engineers spend significant time correlating information
manually. This platform reduces investigation time by combining
monitoring, logging, vector search, and LLM-based reasoning.

## Objectives

• Centralized monitoring • Centralized logging • Automated incident
collection • AI-assisted root cause analysis • RAG-powered runbook
retrieval • Extensible agent framework • Local, low-cost deployment

## Key Features

-   Kind Kubernetes cluster
-   Prometheus + Alertmanager
-   Grafana dashboards
-   Loki + Promtail logging
-   Custom alerts (CPU, Memory, Pod Restart, CrashLoopBackOff)
-   Incident Collector
-   Runbooks
-   Qdrant vector database
-   Ollama local LLM
-   RAG pipeline
-   RCA Agent
-   Report Agent

## High-Level Workflow

Alert → Incident Collector → Context Gathering → RAG Search → LLM
Analysis → RCA Report → Engineer

## Technology Stack

Kubernetes, Kind, Helm, Python, Prometheus, Grafana, Loki, Promtail, Alert Manager
Ollama, Qdrant, LangGraph, SentenceTransformers, Qdrant

## Repository Structure

aiops/ ├── agents/ ├── rag/ ├── runbooks/ ├── sample_incidents/ ├──
monitoring/ ├── reports/ └── docs/

## Enhancements

SRE Copilot, Auto Remediation, Chaos Engineering

## Skills Demonstrated

Kubernetes, DevOps, Observability, AI Engineering, Vector Databases,
Prompt Engineering, Python, Incident Management, SRE , AI Agents

                                                               Architecture

                                                        ┌───────────────────────────────┐
                                                        │       KIND KUBERNETES         │
                                                        │                               │
                                                        │ Application / Microservices   │
                                                        │ Pods / Deployments / Services │
                                                        └───────────────┬───────────────┘
                                                                        │
                                                ┌───────────────────────┼─────────────────────────┐
                                                │                       │                         │
                                                ▼                       ▼                         ▼
                                          PROMETHEUS                PROMTAIL                KUBERNETES
                                          Metrics + Rules              │                   Runtime State
                                                │                      ▼                         │
                                                │                     LOKI                       │
                                                │                     Logs                       │
                                                ▼                                                │
                                          ALERTMANAGER                                           │
                                                │                                                │
                                                │ POST /alertmanager                             │
                                                ▼                                                │
                                ┌─────────────────────────────────────────────────────────────────────────┐
                                │                      SRE COPILOT FASTAPI                                │
                                │                                                                         │
                                │  aiops/sre_copilot/app.py                                               │
                                │                                                                         │
                                │  1. Receive Alertmanager webhook                                        │
                                │  2. Convert alert                                                       │
                                │  3. Generate Incident ID                                                │
                                │  4. Store incident in SQLite                                            │
                                │  5. Queue background investigation                                      │
                                └────────────────────────────┬────────────────────────────────────────────┘
                                                             │
                                                             ▼
                                                    ┌──────────────────┐
                                                    │      SQLite      │
                                                    │  Incident Store  │
                                                    │                  │
                                                    │ QUEUED           │
                                                    │ RUNNING          │
                                                    │ COMPLETED        │
                                                    │ FAILED           │
                                                    │ Approval History │
                                                    └─────────┬────────┘
                                                              │
                                                              ▼
                                ┌─────────────────────────────────────────────────────────────────────────┐
                                │                     LIVE EVIDENCE COLLECTOR                             │
                                │                                                                         │
                                │                     investigator/collector.py                           │
                                │                                                                         │
                                │   ┌─────────────────────────────────────────────────────────────────┐   │
                                │   │ Kubernetes                                                      │   │
                                │   │ • Pod state                                                     │   │
                                │   │ • Container state                                               │   │
                                │   │ • Restart count                                                 │   │
                                │   │ • Events                                                        │   │
                                │   │ • Pod description                                               │   │
                                │   │ • Deployment / workload owner                                   │   │
                                │   │ • Container images                                              │   │
                                │   │ • Resource requests / limits                                    │   │
                                │   └─────────────────────────────────────────────────────────────────┘   │
                                │                                                                         │
                                │   Metrics Server ─────── Current CPU / Memory                           │
                                │                                                                         │
                                │   Prometheus ─────────── Historical metrics                             │
                                │                                                                         │
                                │   Loki ───────────────── Historical logs                                │
                                │                                                                         │
                                │   Kubernetes ─────────── Current + Previous container logs              │
                                └────────────────────────────┬────────────────────────────────────────────┘
                                                             │
                                                             ▼
                                                   ENRICHED INCIDENT EVIDENCE
                                                             │
                                                             ▼
                                ┌─────────────────────────────────────────────────────────────────────────┐
                                │                         LANGGRAPH WORKFLOW                              │
                                │                                                                         │
                                │                         agents/graph.py                                 │
                                │                                                                         │
                                │       START                                                             │
                                │         │                                                               │
                                │         ▼                                                               │
                                │   1. INVESTIGATOR                                                       │
                                │         │                                                               │
                                │         ▼                                                               │
                                │   2. ALERT ASSESSMENT  ←──── Deterministic evidence check               │
                                │         │                                                               │
                                │         ▼                                                               │
                                │   3. RCA                                                                │
                                │         │                                                               │
                                │         ├──────── Alert NOT confirmed ──────┐                           │
                                │         │                                   │                           │
                                │         │                            Deterministic RCA                   │
                                │         │                                                               │
                                │         └──────── Alert confirmed ──────────┐                           │
                                │                                             ▼                           │
                                │                                        RAG + LLM                        │
                                │                                             │                           │
                                │                                             ▼                           │
                                │   4. REMEDIATION  ←────────── Deterministic recommendation              │
                                │         │                                                               │
                                │         ▼                                                               │
                                │   5. VALIDATION   ←────────── Deterministic safety checks               │
                                │         │                                                               │
                                │         ▼                                                               │
                                │   6. REPORT                                                            │
                                │         │                                                               │
                                │         ▼                                                               │
                                │        END                                                              │
                                └────────────────────────────┬────────────────────────────────────────────┘
                                                             │
                                                             ▼
                                                    Store Result in SQLite
                                                             │
                                                             ▼
                                             ┌───────────────────────────────┐
                                             │       SRE COPILOT / UI        │
                                             │                               │
                                             │ Streamlit Dashboard           │
                                             │ Incident API                  │
                                             │ Incident History              │
                                             │ Workflow Timeline             │
                                             │ Read-only Incident Chat       │
                                             └───────────────┬───────────────┘
                                                             │
                                                   Validation passed?
                                                             │
                                                  APPROVED FOR HUMAN REVIEW
                                                             │
                                                             ▼
                                                     HUMAN APPROVAL
                                                             │
                                                   ┌─────────┴──────────┐
                                                   │                    │
                                                REJECT              APPROVE
                                                   │                    │
                                                   ▼                    ▼
                                                 STOP          GITOPS REMEDIATION
                                                                        │
                                                                        ▼
                                                         Deterministic Policy Engine
                                                                        │
                                                         ┌──────────────┼──────────────┐
                                                         │              │              │
                                                         ▼              ▼              ▼
                                                   Root Cause      YAML Policy   Repository
                                                   Resolution       Matching      Manifest
                                                         │              │              │
                                                         └──────────────┼──────────────┘
                                                                        │
                                                                        ▼
                                                              Generate Safe Patch
                                                                        │
                                                                        ▼
                                                                Validate Patch
                                                                        │
                                                                        ▼
                                                              Generate Git Diff
                                                                        │
                                                                        ▼
                                                                  GitHub PR
                                                                        │
                                                                   Human Merge
                                                                        │
                                                                        ▼
                                                                    Argo CD
                                                                        │
                                                                        ▼
                                                                  Kubernetes
                                                                        │
                                                                        ▼
                                                           Argo CD Health Verification
                                                              Synced + Healthy





                                                    RAG KNOWLEDGE FLOW

                                      
                                                OFFLINE                               ONLINE
                                                -------                               ------
                                      
                                         Runbook Markdown                         Incident Alert
                                               │                                      │
                                               ▼                                      ▼
                                         nomic-embed-text                        nomic-embed-text
                                               │                                      │
                                               ▼                                      ▼
                                           Embedding                              Query Vector
                                               │                                      │
                                               ▼                                      │
                                            Qdrant  ◄─────────────────────────────────┘
                                               │
                                               │ Similarity Search
                                               ▼
                                         Top Runbooks
                                               │
                                               ▼
                                         RCA Context
                                               │
                                               ▼
                                       Evidence + Assessment
                                               │
                                               ▼
                                         Qwen2.5:1.5b
                                               │
                                               ▼
                                         Grounded RCA



OLLAMA:                   
                                                              OLLAMA
                                                                 │
                                                      ┌──────────┴───────────┐
                                                      │                      │
                                                      ▼                      ▼
                                               Embedding Model           LLM Model
                                          
                                             nomic-embed-text         qwen2.5:1.5b
                                                      │                      │
                                                      ▼                      ▼
                                               RAG vectors            RCA reasoning







GITOPS Patch Generation plan:
                                                         Root Cause
                                                              ↓
                                                          OOMKilled policy
                                                              ↓
                                                          Find deployment YAML
                                                              ↓
                                                          Read existing resources
                                                              ↓
                                                          Generate allowed deterministic operation
                                                              ↓
                                                          Validate
                                                              ↓
                                                          Produce Git diff



SRE COPILOTCHAT:
                                                                SRE
                                                                 │
                                                                 │ "Why did this pod restart?"
                                                                 ▼
                                                                Incident Chat
                                                                 │
                                                                 ├── Stored incident evidence
                                                                 ├── Investigation
                                                                 ├── RCA
                                                                 ├── Validation
                                                                 └── Report
                                                                 │
                                                                 ▼
                                                                Explanation





