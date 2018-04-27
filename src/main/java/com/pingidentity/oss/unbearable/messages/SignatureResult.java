package com.pingidentity.oss.unbearable.messages;

import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class SignatureResult
{
    static final SignatureResult VALID = new SignatureResult(Status.VALID);
    static final SignatureResult INVALID = new SignatureResult(Status.INVALID);

    public enum Status {VALID, INVALID, UNEVALUATED}

    private Status status = Status.UNEVALUATED;

    private List<String> commentary = new LinkedList<String>();

    SignatureResult(Status status)
    {
        this.status = status;
    }

    public Status getStatus()
    {
        return status;
    }

    void setStatus(Status status)
    {
        this.status = status;
    }

    void addComment(String comment)
    {
        commentary.add(comment);
    }

    public List<String> getCommentary()
    {
        return commentary;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append(status);
        if (hasCommentary())
        {
            sb.append(" commentary: ").append(commentary);
        }

        return sb.toString();
    }

    public boolean hasCommentary()
    {
        return !commentary.isEmpty();
    }
}
