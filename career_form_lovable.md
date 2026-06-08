# TransCrypts Careers Form — Lovable Integration Guide

This guide gives you **two ways** to add the careers application form to your
Lovable-built `transcrypts.com` website. Pick whichever feels easier.

---

## Option A — Easiest: Paste this prompt into Lovable's chat

Open your project in Lovable, then paste this prompt verbatim into the chat:

```
Add a /careers page with a job application form.

The form should have:
- A heading "Apply to TransCrypts" with subtitle "We're hiring! Submit your application below."
- A position dropdown (default option "Open Application — any suitable role")
  with these positions: FullStack Developer, Software Engineer, Frontend Engineer,
  DevOps Engineer, Product Manager, Account Executive
- Required text input for full name
- Required email input
- Optional phone input (tel)
- Optional LinkedIn URL input
- Required file input that accepts only .pdf and .docx
- Optional textarea for cover letter / brief intro
- A submit button styled with the TransCrypts green colour (#6DC49A)
- Show a success or error message under the form after submission

On submit, the form should POST to this URL as multipart/form-data:
  https://YOUR-RENDER-APP.onrender.com/api/careers/apply

Form fields to send: name, email, phone, position, linkedin_url, resume,
cover_letter.

Use shadcn/ui components (Input, Button, Select, Textarea, Label) and
Tailwind CSS for styling. Use the company's existing colour palette.
On successful submission show: "Thank you for applying! We've received your
application and our team will review it shortly." Then reset the form.
On error show the error message returned by the API.

Add a "Careers" link to the main navigation pointing to /careers.
```

Replace `YOUR-RENDER-APP.onrender.com` with your actual Render URL before
sending. Lovable's AI will generate the entire page and wire up the API call.

---

## Option B — Drop-in React component

If you prefer to add the file yourself (via Lovable's GitHub sync or code
editor), copy the component below into `src/pages/Careers.tsx` (or wherever
your pages live), then add the route to your router.

```tsx
// src/pages/Careers.tsx
import { useState, FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CheckCircle2, AlertCircle, Loader2 } from "lucide-react";

// ════════════════════════════════════════════════════════════════════════
//  CONFIGURATION — replace with your actual Render URL
// ════════════════════════════════════════════════════════════════════════
const API_BASE_URL = "https://YOUR-RENDER-APP.onrender.com";
const API_KEY = ""; // optional, only if CAREERS_API_KEY env var is set on Render
// ════════════════════════════════════════════════════════════════════════

const POSITIONS = [
  "FullStack Developer",
  "Software Engineer",
  "Frontend Engineer",
  "DevOps Engineer",
  "Product Manager",
  "Account Executive",
];

type Status =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "success"; message: string }
  | { kind: "error";   message: string };

export default function Careers() {
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [position, setPosition] = useState<string>("");

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setStatus({ kind: "submitting" });

    const fd = new FormData(e.currentTarget);
    if (position) fd.set("position", position);

    try {
      const headers: Record<string, string> = {};
      if (API_KEY) headers["X-API-Key"] = API_KEY;

      const res = await fetch(`${API_BASE_URL}/api/careers/apply`, {
        method: "POST",
        body: fd,
        headers,
      });
      const data = await res.json();

      if (res.ok && data.ok) {
        setStatus({
          kind: "success",
          message: data.message ??
            "Thank you for applying! We've received your application.",
        });
        e.currentTarget.reset();
        setPosition("");
      } else {
        setStatus({
          kind: "error",
          message: data.message ?? "Something went wrong. Please try again.",
        });
      }
    } catch (err) {
      setStatus({
        kind: "error",
        message: `Network error: ${(err as Error).message}`,
      });
    }
  };

  return (
    <div className="min-h-screen bg-emerald-50/30 py-12 px-4">
      <div className="max-w-2xl mx-auto">
        <div className="mb-8 text-center">
          <h1 className="text-4xl font-bold text-emerald-900 mb-2">
            Apply to TransCrypts
          </h1>
          <p className="text-slate-600">
            We're hiring! Submit your application below and our team will be in
            touch.
          </p>
        </div>

        <Card className="shadow-lg border-emerald-200">
          <CardHeader>
            <CardTitle className="text-emerald-800">Application Form</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4"
                  encType="multipart/form-data">

              <div className="space-y-2">
                <Label htmlFor="position">
                  Position you're applying for{" "}
                  <span className="text-xs text-slate-500 font-normal">
                    (leave blank for an open application)
                  </span>
                </Label>
                <Select value={position} onValueChange={setPosition}>
                  <SelectTrigger id="position">
                    <SelectValue placeholder="— Open Application (any suitable role) —" />
                  </SelectTrigger>
                  <SelectContent>
                    {POSITIONS.map(p => (
                      <SelectItem key={p} value={p}>{p}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="name">
                  Full name <span className="text-rose-600">*</span>
                </Label>
                <Input id="name" name="name" required />
              </div>

              <div className="space-y-2">
                <Label htmlFor="email">
                  Email <span className="text-rose-600">*</span>
                </Label>
                <Input id="email" name="email" type="email" required />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="phone">Phone</Label>
                  <Input id="phone" name="phone" type="tel" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="linkedin_url">LinkedIn</Label>
                  <Input id="linkedin_url" name="linkedin_url" type="url"
                         placeholder="https://linkedin.com/in/..." />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="resume">
                  Resume (PDF or DOCX) <span className="text-rose-600">*</span>
                </Label>
                <Input id="resume" name="resume" type="file" required
                       accept=".pdf,.docx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" />
              </div>

              <div className="space-y-2">
                <Label htmlFor="cover_letter">
                  Cover letter / brief intro{" "}
                  <span className="text-xs text-slate-500 font-normal">
                    (optional)
                  </span>
                </Label>
                <Textarea id="cover_letter" name="cover_letter" rows={5}
                          placeholder="Tell us why you're a great fit…" />
              </div>

              <Button type="submit"
                      disabled={status.kind === "submitting"}
                      className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-semibold py-6">
                {status.kind === "submitting" ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Submitting…</>
                ) : "Submit Application"}
              </Button>

              {status.kind === "success" && (
                <div className="flex items-start gap-2 p-4 rounded-lg
                                bg-emerald-50 border border-emerald-200">
                  <CheckCircle2 className="h-5 w-5 text-emerald-600 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-emerald-900">{status.message}</p>
                </div>
              )}
              {status.kind === "error" && (
                <div className="flex items-start gap-2 p-4 rounded-lg
                                bg-rose-50 border border-rose-200">
                  <AlertCircle className="h-5 w-5 text-rose-600 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-rose-900">{status.message}</p>
                </div>
              )}

              {/* Privacy consent — required checkbox */}
              <div className="flex items-start gap-3 p-3 bg-emerald-50
                              border border-emerald-200 rounded-lg">
                <input
                  type="checkbox"
                  id="privacyConsent"
                  required
                  className="mt-0.5 h-4 w-4 accent-emerald-600 flex-shrink-0"
                />
                <label htmlFor="privacyConsent"
                       className="text-sm text-slate-700 cursor-pointer leading-relaxed">
                  I have read and agree to the{" "}
                  <a href="#privacy-notice"
                     className="text-emerald-600 hover:underline font-medium">
                    Privacy Notice
                  </a>
                  {" "}<span className="text-rose-600">*</span>
                </label>
              </div>

            </form>

            {/* Privacy Notice — expandable */}
            <details id="privacy-notice" className="mt-4">
              <summary className="text-sm font-semibold text-slate-600
                                   cursor-pointer hover:text-slate-800">
                Privacy Notice — how we handle your information
              </summary>
              <div className="mt-3 p-4 bg-slate-50 border border-slate-200
                              rounded-lg text-xs text-slate-600 space-y-2
                              leading-relaxed">
                <p><strong>What we collect:</strong> Your name, email, phone,
                LinkedIn profile, and your resume. We may also collect your
                cover letter and chosen position.</p>
                <p><strong>How we use it:</strong> Solely to assess your suitability
                for roles at TransCrypts. Your resume is analysed by an AI system
                (Anthropic Claude) to extract professional information and categorise
                skills automatically. All hiring decisions involve human review.</p>
                <p><strong>Who processes your data:</strong> Authorised TransCrypts
                HR staff, and service providers acting on our behalf: Supabase Inc.
                (database, USA), Render Inc. (hosting, USA), Anthropic PBC (AI
                parsing, USA), and our email provider. Data may be transferred to
                and processed in the United States under appropriate contractual
                protections.</p>
                <p><strong>Retention:</strong> Applications are retained for up to
                2 years from submission or last activity, then anonymised or deleted.</p>
                <p><strong>Your rights:</strong> You may request access to, correction
                of, or deletion of your data. EU residents have additional rights.
                Email{" "}
                <a href="mailto:hr@transcrypts.com"
                   className="text-emerald-600 hover:underline">
                  hr@transcrypts.com
                </a>{" "}— we respond within 30 days. Canadian residents may also
                contact the{" "}
                <a href="https://www.priv.gc.ca" target="_blank" rel="noreferrer"
                   className="text-emerald-600 hover:underline">
                  Office of the Privacy Commissioner of Canada
                </a>.
                </p>
              </div>
            </details>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
```

### Wiring up the route

Find where your other routes are defined (probably `src/App.tsx` or
`src/main.tsx`) and add this import + route:

```tsx
import Careers from "./pages/Careers";

// inside <Routes>:
<Route path="/careers" element={<Careers />} />
```

### Add to navigation

Find your navbar component (often `src/components/Navbar.tsx`) and add:

```tsx
<Link to="/careers" className="hover:text-emerald-600">
  Careers
</Link>
```

---

## Testing

1. Save the file → Lovable rebuilds automatically
2. Visit `/careers` on your site
3. Fill in the form with a test PDF resume → click Submit
4. You should see the success message
5. Open your **TransCrypts Resume DB** Render URL → log in → the new
   applicant should appear with a blue "Career Website" badge

If submission fails:
- Check browser DevTools → Network tab → look for the `/api/careers/apply`
  request → click it to see the error response
- Common issues:
  - Wrong `API_BASE_URL` (check Render dashboard)
  - Render service is sleeping (free tier sleeps after 15 min — first
    request takes ~30 seconds to wake it up)
  - CORS error (shouldn't happen — already handled in Flask)
  - Rate-limit hit (5 submissions per hour per IP — wait an hour)

---

## Per-job apply buttons (advanced)

If you have a job listings page where each job has its own "Apply" button,
pass the position via React Router state or query string:

```tsx
// On the job listing page:
<Link to="/careers?position=FullStack%20Developer">Apply</Link>
```

Then in `Careers.tsx`, read it on mount:

```tsx
import { useSearchParams } from "react-router-dom";
// ...
const [searchParams] = useSearchParams();
useEffect(() => {
  const pre = searchParams.get("position");
  if (pre) setPosition(pre);
}, [searchParams]);
```

The dropdown will be pre-selected with the role they clicked.
