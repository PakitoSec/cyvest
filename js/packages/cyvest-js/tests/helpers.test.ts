import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { parseCyvest } from "../src";

describe("parseCyvest", () => {
  it("accepts resolver metadata stored in observable extra", () => {
    const fixtureUrl = new URL(
      "../../cyvest-app/src/investigations/cyvest_visual.json",
      import.meta.url,
    );
    const payload = JSON.parse(readFileSync(fixtureUrl, "utf8"));
    const observable = payload.observables["obs:file:root"];
    observable.extra = {
      resolver_data: {
        "asset-directory": {
          profile: {
            owner: "security",
            status: "active",
          },
        },
      },
    };

    const investigation = parseCyvest(payload);

    expect(investigation.observables["obs:file:root"].extra).toEqual(
      observable.extra,
    );
  });
});
