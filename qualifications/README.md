# USF qualification corpus

Versioned qualification fixtures with **known answers**, derived from the design
and historical USF failure classes (build task §8.2). Each case declares a
`dimension` (one of `usf_factory.enums.SCORE_DIMENSIONS`) and a `task_class`, and
is graded deterministically.

- `*.yaml` here are the **public regression** cases.
- `holdout/*.yaml` are **hidden holdout** variants (`holdout: true`) used to
  detect benchmark overfitting. Rotate these periodically.

Graders: `exact`, `contains`, `not_contains`, `regex`, `iri_exact`, `choice`,
`set_equal`, `json_schema`, `uncertainty`.

These prompts are generic and **contain no `/usf` source**. Running them against
a real model is billable and disabled by default.
