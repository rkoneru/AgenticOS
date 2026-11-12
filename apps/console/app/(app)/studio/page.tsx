"use client";
import { PageHeader } from "@/components/common";
import { StudioCanvas } from "@/components/studio/studio-canvas";

export default function StudioPage() {
  return (
    <>
      <title>Agent Studio - AXIS Console</title>
      <PageHeader
        title="Agent Studio"
        description="Compose an ABL blueprint visually: add nodes, connect the routing pipeline, then review and publish through the same validator and publish flow as the YAML editor."
      />
      <StudioCanvas />
    </>
  );
}
