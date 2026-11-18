#!/usr/bin/env python3
"""Private reader stop projection for Issue #37 partial evidence."""
from transfer_revocation_timing import NS_PER_MS, StopKind, StopObservation


def _ms(ns):
    return round(ns / NS_PER_MS, 3)


def reader_stop_or_fail(evidence, trigger_state, *, timed_out, received, now_ns,
                        lower_ns=None, resume_ns=None):
    """Copy observed reader facts before a stored reader error can raise."""
    reader_resume_ns = trigger_state.get("reader_resume_ns")
    evidence.set_timestamp("reader_resume_ns", reader_resume_ns)
    if reader_resume_ns is not None and lower_ns is not None:
        evidence.set_metric("post_trigger_pause_ms", _ms(reader_resume_ns - lower_ns))
        evidence.set_metric("reader_resume_after_lower_ms", _ms(reader_resume_ns - lower_ns))
        if resume_ns is not None:
            evidence.set_metric(
                "reader_resume_delta_from_target_ms",
                _ms(reader_resume_ns - resume_ns),
            )
    trigger_state["reader_alive_after_main_join"] = bool(timed_out)
    evidence.set_reader_state(
        finished=bool(trigger_state.get("reader_finished")),
        alive_after_main_join=bool(timed_out),
        error_class=trigger_state.get("reader_error_class"),
    )
    evidence.enter_phase("transport_stop_observe")
    if timed_out:
        evidence.note("transport_stop_observe", "reader_timeout")
        evidence.mark_unproven()
        stop = StopObservation(StopKind.TIMEOUT, now_ns, received)
        evidence.set_stop(stop.report())
        evidence.mark_cleanup_unresolved("reader_timeout")
        evidence.finish_phase("transport_stop_observe")
        return stop
    if not trigger_state.get("reader_finished"):
        evidence.fail("transport_stop_observe", "reader_missing_completion")
        raise evidence.safe_failure("reader_missing_completion")
    error_class = trigger_state.get("reader_error_class")
    if error_class is not None:
        evidence.fail(
            "transport_stop_observe", error_class,
            trigger_state.get("reader_error_errno"),
        )
        raise evidence.safe_failure(error_class)
    stop = trigger_state.get("stop")
    if stop is None:
        evidence.fail("transport_stop_observe", "reader_missing_completion")
        raise evidence.safe_failure("reader_missing_completion")
    evidence.set_stop(stop.report())
    evidence.finish_phase("transport_stop_observe")
    return stop
