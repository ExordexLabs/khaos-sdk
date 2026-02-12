"""Framework adapters that instrument third-party runtimes for telemetry."""

from .langgraph import wrap_langgraph
from .crewai import wrap_crewai
from .prefect import wrap_prefect
from .airflow import wrap_airflow
from .dagster import wrap_dagster
from .autogen import wrap_autogen

__all__ = ["wrap_langgraph", "wrap_crewai", "wrap_prefect", "wrap_airflow", "wrap_dagster", "wrap_autogen"]
