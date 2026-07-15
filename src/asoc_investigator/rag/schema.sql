-- Run this in the Supabase SQL editor (or `supabase db push`) once per
-- project. See docs/ARCHITECTURE.md "RAG over prior incidents".
--
-- IMPORTANT: vector(1536) below matches OpenAI's text-embedding-3-small
-- (rag/embeddings.py OpenAIEmbedder), which is used automatically whenever
-- OPENAI_API_KEY is set — already required for the agents, so this is the
-- practical default. If you're deliberately running WITHOUT OPENAI_API_KEY
-- against a live Supabase project (falls back to the 256-dim
-- HashingEmbedder), change every `vector(1536)` here to `vector(256)`.

create extension if not exists vector;

create table if not exists incidents (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  -- Already masked at write time — see docs/ARCHITECTURE.md. No PII is
  -- ever stored in this table; there is no unmask path for RAG results.
  masked_summary text not null,
  indicator_types text[] not null default '{}',
  resolution text,
  confidence double precision,
  embedding vector(1536)
);

create index if not exists incidents_embedding_idx
  on incidents using ivfflat (embedding vector_cosine_ops)
  with (lists = 100);

create or replace function match_incidents (
  query_embedding vector(1536),
  match_count int default 5
)
returns table (
  id uuid,
  masked_summary text,
  indicator_types text[],
  resolution text,
  confidence double precision,
  similarity double precision
)
language sql stable
as $$
  select
    id,
    masked_summary,
    indicator_types,
    resolution,
    confidence,
    1 - (embedding <=> query_embedding) as similarity
  from incidents
  order by embedding <=> query_embedding
  limit match_count;
$$;
