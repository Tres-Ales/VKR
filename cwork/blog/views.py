import datetime

from django.contrib.auth import get_user_model
from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, get_object_or_404

from .forms import PostForm
from .models import Post
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
user = get_user_model()

def post_list(request):
    posts = Post.published.all()
    return render(request, 'users/post/list.html', {'posts': posts})

def post_detail(request, year, month, day, post):
    post = get_object_or_404(Post, slug=post,
                                   status='published',
                                   publish__year=year,
                                   publish__month=month,
                                   publish__day=day)
    return render(request,'users/post/detail.html', {'post': post})

# VIEW FOR CREATING POST BY USER
@login_required()
def create_post(request):
    User = get_user_model()
    if request.method == 'POST':
        post_form = PostForm(data=request.POST)

        if post_form.is_valid():
            # Create Comment object but don't save to database yet
            new_post = post_form.save(commit=False)
            # Assign the current post to the comment
            new_post.publshed = datetime.date.today()
            text = new_post.title
            text = text.replace(' ','-').lower()
            new_post.slug = text
            new_post.author = request.user
            new_post.status = 'published'
            new_post.save()

        return render(request, 'users/dashboard.html', {'section': 'dashboard'})
    else:
         form = PostForm()
    return render(request, 'users/post/create_post.html', {'form': form})

