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

## License

Educational / Portfolio project.
