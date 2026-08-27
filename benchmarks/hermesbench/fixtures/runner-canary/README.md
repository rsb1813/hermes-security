# HermesBench Runner Canary Fixture

This directory documents the public synthetic source shape used by the zero-cost runner Canary. The test materializes vulnerable and fixed snapshots in a temporary directory so the repository contains no private grading data.

The fake adapter reads only the supplied snapshot source bytes and returns a deterministic localization result for the synthetic vulnerable shape. It makes no model call, network request, or subprocess invocation.

The test keeps its private oracle outside the snapshot root, executor scratch directory, and run-output root. This fixture proves the abstract request and visible-directory boundary only. Task 4 is responsible for proving actual Docker mounts and container isolation.
