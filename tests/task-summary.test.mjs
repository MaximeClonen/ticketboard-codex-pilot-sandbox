import assert from "node:assert/strict";
import test from "node:test";

import { createTaskSummary } from "../src/task-summary.mjs";

test("creates a normal task summary deterministically", () => {
  const input = {
    title: "Plan sprint",
    description: "Review tickets today",
  };
  const expected = {
    title: "Plan sprint",
    description: "Review tickets today",
    wordCount: 5,
  };

  assert.deepStrictEqual(
    [createTaskSummary(input), createTaskSummary(input)],
    [expected, expected],
  );
});

test("trims the title and description", () => {
  assert.deepStrictEqual(
    createTaskSummary({
      title: "  Plan sprint  ",
      description: "  Review tickets today  ",
    }),
    {
      title: "Plan sprint",
      description: "Review tickets today",
      wordCount: 5,
    },
  );
});

test("uses an empty description when it is omitted", () => {
  assert.deepStrictEqual(createTaskSummary({ title: "Plan sprint" }), {
    title: "Plan sprint",
    description: "",
    wordCount: 2,
  });
});

test("rejects an empty title with a stable error", () => {
  assert.throws(
    () => createTaskSummary({ title: "   " }),
    {
      name: "Error",
      message: "Title must not be empty.",
    },
  );
});

test("counts words across whitespace in both fields", () => {
  assert.equal(
    createTaskSummary({
      title: "Plan\tlaunch",
      description: "Review\n tickets   today",
    }).wordCount,
    5,
  );
});
