export function createTaskSummary(input) {
  const title = input.title.trim();

  if (title === "") {
    throw new Error("Title must not be empty.");
  }

  const description = (input.description ?? "").trim();
  const wordCount = `${title} ${description}`
    .split(/\s+/)
    .filter(Boolean).length;

  return {
    title,
    description,
    wordCount,
  };
}
